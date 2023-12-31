#!/usr/bin/env python3

"""
Determine connection parameters for the given Network Connect VPN using
Microsoft's SAML single sign-on and output them for OpenConnect.
"""

__version__ = "0.0.1"

from argparse import ArgumentParser
from collections import namedtuple
from getpass import getpass
from html.parser import HTMLParser
from socket import socketpair
from subprocess import Popen
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse
from urllib.request import Request
import cgi
import json
import logging
import shlex
import sys
import urllib.request

import pyotp
import keyring


# The known HTML form names and the submit buttons to be used.
FORMS = {
    "formSAMLSSO": (),
    "frmConfirmation": set(("btnContinue",)),
    "hiddenform": (),
    "loginForm": (),
}


Form = namedtuple("Form", ["action", "fields"])


class FormParser(HTMLParser):
    """
    I extract forms from a web page.

    Additionally, if there is a <script> tag which sets the global $Config
    variable, I store its value.
    """

    def __init__(self):
        super().__init__()
        self.forms = {}
        self.config = {}
        self.current = None
        self.script = 0

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self.script += 1

        attrs = dict(attrs)
        if tag == "form":
            if self.current:
                raise RuntimeError("Nested forms")
            self.current = attrs.get("name") or attrs["id"]
            if self.current in self.forms:
                logging.warning("%s: form redefined", self.current)
            self.forms[self.current] = Form(attrs.get("action", ""), {})

        elif self.current and tag == "input" and "name" in attrs:
            # Only include the correct submit button.
            if (
                attrs.get("type") == "submit"
                and attrs["name"] not in FORMS[self.current]
            ):
                logging.info(
                    "%s: %s: unknown submit button", self.current, attrs["name"]
                )
                return

            form = self.forms[self.current]
            if attrs["name"] in form.fields:
                logging.warning("%s: %s: field redefined", self.current, attrs["name"])
            form.fields[attrs["name"]] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "script":
            self.script -= 1

        if tag == "form":
            self.current = None

    def handle_data(self, data):
        if self.script:
            start = data.find("$Config=")
            end = data.rfind("}")
            if start >= 0 and end >= 0:
                self.config = json.loads(data[8 + start: 1 + end])

    def error(self, message: str) -> Any:
        pass


class FormProcessor:
    """
    I load, fill in and send HTML forms. I provide access to the cookies
    exchanged with the server.
    """

    def __init__(self, user_agent="DSClient; PulseLinux", password=None):
        self.password = password
        self.cookies = urllib.request.HTTPCookieProcessor()
        self.opener = urllib.request.build_opener(self.cookies)
        if user_agent:
            self.opener.addheaders = (("User-Agent", user_agent),)
        self.url = None

    def load_url(self, url):
        """
        Load the given URL or Request and return the Response.
        """
        logging.info("> %s", url.full_url if isinstance(url, Request) else url)
        res = self.opener.open(url)
        self.url = res.url
        logging.debug("< %s", self.url)

        return res

    def parse_url(self, url, parser):
        """
        Load from the given URL or Request and apply the parser to the result.
        """
        with self.load_url(url) as res:
            if self.get_cookie("DSID"):
                return parser
            _, params = cgi.parse_header(res.getheader("content-type"))
            while True:
                chunk = res.read(1024)
                if not chunk:
                    break
                parser.feed(chunk.decode(params.get("charset", "utf-8")))
        parser.close()
        return parser

    def get_json(self, url, data):
        """
        Invoke a JSON API endpoint.
        """
        logging.debug("> %s", data)
        req = Request(
            url,
            data=json.dumps(data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with self.load_url(req) as res:
            res = json.load(res)
            logging.debug("< %s", res)
            return res

    def process_forms(self, url):
        """
        Keep reading from the URL or Request while they contain known
        forms, filling them in and returning them. Stop when a DSID cookie
        is received or when there are no forms, returning the $Config
        object, if any.
        """
        while True:
            forms = self.parse_url(url, FormParser())
            logging.debug("< forms=%s", forms.forms)
            logging.debug("< config=%s", forms.config)
            if not forms.forms:
                return forms.config

            # Handle an arbitrary known form.
            name = next((n for n in forms.forms if n in FORMS), None)

            form = forms.forms[name]
            if "Password" in form.fields:
                if self.password:
                    form.fields["Password"] = self.password
                    self.password = None
                else:
                    form.fields["Password"] = getpass("Password: ")

            logging.debug("> %s", form.fields)
            url = urljoin(self.url, form.action)
            url = Request(url, data=urlencode(form.fields).encode())

    def get_cookie(self, name, fallback=None):
        """
        Return the named cookie if it has been received.
        """
        for cookie in self.cookies.cookiejar:
            if name == cookie.name:
                return cookie.value
        return fallback

    def get_cookies_as_string(self):
        """
        Return list of set cookies from the authentication as a string
        """
        cookie_string = ""
        for cookie in self.cookies.cookiejar:
            if cookie.name in [
                "DSSignInURL",
                "DSLaunchURL",
                "DSID",
                "DSDID",
                "DSFirstAcess",
                "DSPSALPREF",
                "DSLastAccess",
            ]:
                cookie_string += cookie.name + "=" + cookie.value + "; "
        return cookie_string

    def set_cookie(self, name, value):
        """
        Set the named cookie to the given value.
        """
        for cookie in self.cookies.cookiejar:
            if name == cookie.name:
                cookie.value = value


def choice(prompt, choices):
    """
    Interactively give the user a choice. The choices are expected to be a
    dictionary of options and their descriptions. The chosen option is
    returned.
    """
    choices = list(choices.items())
    num = 0
    while num < 1 or len(choices) < num:
        for i, item in enumerate(choices):
            sys.stderr.write(f" {1 + i}. {' '.join(item)}\n")
        sys.stderr.write(f"{prompt}: [1] ")
        num = input()
        if not num:
            num = 1
        else:
            try:
                num = int(num)
            except ValueError:
                num = 0
    return choices[num - 1][0]


def do_login(form_proc, config, username):
    """
    Perform a login with the given username or redirect to the federated
    login page.
    """
    data = {
        "flowToken": config["sFT"],
        "originalRequest": config["sCtx"],
        "username": username,
    }
    url = config["urlGetCredentialType"]
    creds = form_proc.get_json(url, data)
    if "FederationRedirectUrl" in creds["Credentials"]:
        return urljoin(form_proc.url, creds["Credentials"]["FederationRedirectUrl"])

    if form_proc.password:
        password = form_proc.password
    else:
        password = keyring.get_password("oc-msft", username) or getpass("Password: ")
        keyring.set_password("oc-msft", username, password)
    data = {
        "canary": config["canary"],
        "ctx": config["sCtx"],
        "flowToken": creds["FlowToken"],
        "hpgrequestid": config["sessionId"],
        "login": username,
        "passwd": password,
    }
    logging.debug("> %s", data)
    url = urljoin(form_proc.url, config["urlPost"])
    return Request(url, data=urlencode(data).encode())


def do_authentication(form_proc, config, username, totp):
    """
    Pick one of the available authentication methods and try to
    authenticate with it.
    """

    # Pick an authentication method.
    user_proofs = {
        proof["authMethodId"]: proof["display"] for proof in config["arrUserProofs"]
    }
    if totp and "PhoneAppOTP" in user_proofs:
        method = "PhoneAppOTP"
    else:
        method = choice("Choose an authentication method", user_proofs)

    data = {
        "AuthMethodId": method,
        "Method": "BeginAuth",
        "ctx": config["sCtx"],
        "flowToken": config["sFT"],
    }
    begin_auth = form_proc.get_json(config["urlBeginAuth"], data)

    if not begin_auth["Success"]:
        logging.warning(begin_auth["Message"]) 

    # Perform the authentication.
    token = totp.now() if (totp and method == "PhoneAppOTP") else getpass("OTP token: ")
    data = {
        "AdditionalAuthData": token,
        "AuthMethodId": method,
        "Ctx": config["sCtx"],
        "FlowToken": begin_auth["FlowToken"],
        "Method": "EndAuth",
        "PollCount": 1,
        "SessionId": begin_auth["SessionId"],
    }
    end_auth = form_proc.get_json(config["urlEndAuth"], data)

    if not end_auth["Success"]:
        logging.warning(end_auth["Message"])

    data = {
        "canary": config["canary"],
        "flowToken": end_auth["FlowToken"],
        "hpgrequestid": begin_auth["SessionId"],
        "login": username,
        "mfaAuthMethod": method,
        "otc": token,
        "request": config["sCtx"],
    }
    logging.debug("> %s", data)
    url = urljoin(form_proc.url, config["urlPost"])
    return Request(url, data=urlencode(data).encode())


def tncc_preauth(wrapper, dspreauth, dssignin, host):
    """
    Run a TNCC host checker script and return the updated DSPREAUTH cookie.
    """
    logging.debug("Trying to run TNCC/Host Checker script: %s %s", wrapper, host)
    sys.stderr.write("Emulating host-checker requirement.\n")
    sock0, sock1 = socketpair()
    Popen([wrapper, host], stdin=sock1, stdout=sys.stderr, text=True)
    sock1.close()
    sock0.sendall(
        f"start\nIC={host}\nCookie={dspreauth}\nDSSIGNIN={dssignin}\n".encode("ascii")
    )
    status, _, dspreauth, buf = sock0.recv(4096).decode("ascii").split("\n", 3)
    if status != "200":
        raise RuntimeError(f"tncc status={status}")
    logging.debug("Got new DSPREAUTH cookie from TNCC: %s", dspreauth)
    return dspreauth


def login(args):
    """
    Perform a Microsoft SAML SSO login and return the connection parameters.

    Arguments are:
        password    Password, optional.
        secret      TOTP secret, optional.
        server      Endpoint.
        user        Username, optional.
        user_agent  User-Agent, optional.
        verbose     Verbosity, optional.
        wrapper     TNCC wrapper script, optional.
    """
    logging.basicConfig(level=max(0, logging.WARNING - 10 * (args.verbose or 0)))
    form_proc = FormProcessor("", args.password)
    totp = pyotp.TOTP(args.secret) if args.secret else None
    url = args.server
    username = args.user
    wrapper = args.wrapper

    while True:
        config = form_proc.process_forms(url)

        if form_proc.get_cookie("DSID"):
            return {
                "CONNECT_URL": form_proc.url,
                "COOKIE": form_proc.get_cookies_as_string(),
                "HOST": urlparse(form_proc.url).netloc,
            }

        if "urlGetCredentialType" in config:
            # Step one: login or redirect to federated login page.
            sys.stderr.write("handing back to microsoft SSO for auth\n")
            if not username:
                sys.stderr.write("Username: ")
                username = input()

            url = do_login(form_proc, config, username)

        elif "arrUserProofs" in config:
            # Step two: perform authentication.
            url = do_authentication(form_proc, config, username, totp)
            totp = None
            username = None

        elif "urlPost" in config:
            # Step three: not sure what this is for.
            data = {
                "ctx": config["sCtx"],
                "flowToken": config["sFT"],
                "hpgrequestid": config["sessionId"],
            }
            url = urljoin(form_proc.url, config["urlPost"])
            url = Request(url, data=urlencode(data).encode())

        elif wrapper and form_proc.get_cookie("DSPREAUTH"):
            # Step four: run host checker.
            url = form_proc.url
            dspreauth = tncc_preauth(
                wrapper,
                form_proc.get_cookie("DSPREAUTH"),
                form_proc.get_cookie("DSSIGNIN", "null"),
                urlparse(url).netloc,
            )
            form_proc.set_cookie("DSPREAUTH", dspreauth)
            wrapper = None

        else:
            raise RuntimeError("Failed to find or parse web form in login page.")


def parse_args(args=None):
    """
    Process command-line arguments.
    """
    parser = ArgumentParser(description=sys.modules[__name__].__doc__)
    parser.add_argument("-A", "--user-agent", help="user agent to send")
    parser.add_argument("-p", "--password", help="login password")
    parser.add_argument("-s", "--secret", help="TOTP secret (SHA1 base32)")
    parser.add_argument("-u", "--user", help="login username")
    parser.add_argument("-v", "--verbose", action="count", help="increase verbosity")
    parser.add_argument("-w", "--wrapper", help="wrapper script")
    parser.add_argument("-S", "--server", help="VPN server")
    return parser.parse_args(args)


def main():
    """
    Invoke login() with the command-line arguments and print the result.
    """
    env = login(parse_args())
    for key, val in env.items():
        print(f"{key}={shlex.quote(val)};")


if __name__ == "__main__":
    main()
