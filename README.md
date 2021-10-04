oc_msft
=======

This tool performs a web-based VPN login for Network Connect VPNs that use
Microsoft's SAML single sign-on. This method redirects to
https://login.microsoftonline.com/jsdisabled if JavaScript is disabled in
an attempt to prevent browser-less logins.

The script outputs connection parameters that can be used to establish a
VPN connection with [OpenConnect][OC]. The script name is an abbreviation
for OpenConnect and Microsoft.

This script parses JSON objects sent by the server and processes them like
the JavaScript code that is embedded in the page. This way, the login can
be performed without resorting to a browser.


Installation
------------

The script can be installed using the following command:

    pip install git+https://gitlab.com/jkuebart/oc-msft.git#egg=oc_msft


Usage
-----

    usage: oc_msft [-h] [-A USER_AGENT] [-p PASSWORD] [-s SECRET] [-u USER] [-v]
                   [-w WRAPPER]
                   server

    Determine connection parameters for the given Network Connect VPN using
    Microsoft's SAML single sign-on and output them for OpenConnect.

    positional arguments:
      server                VPN server

    optional arguments:
      -h, --help            show this help message and exit
      -A USER_AGENT, --user-agent USER_AGENT
                            user agent to send
      -p PASSWORD, --password PASSWORD
                            login password
      -s SECRET, --secret SECRET
                            TOTP secret (SHA1 base32)
      -u USER, --user USER  login username
      -v, --verbose         increase verbosity
      -w WRAPPER, --wrapper WRAPPER
                            trojan wrapper script

The wrapper script can be Russ Dill's original [`tncc.py`][TNCC] or one of
the scripts in OpenConnect's `trojan` directory.

The output of the script is modelled after OpenConnect's
[`--authenticate`][AUTH] option:

    COOKIE=5aea159e5a2884b9dcf50565eb1e2ee7
    HOST=vpn.example.com
    CONNECT_URL=https://vpn.example.com/dana/home/starter0.cgi?check=yes

It can therefore be used just like OpenConnect's `--authenticate` option:

    eval $(
        oc_msft.py \
            https://vpn.example.com/ \
            username \
            password \
            secret \
            ./tncc-emulate.py
    )
    [ -n "$COOKIE" ] && printf '%s\n' "$COOKIE" |
    sudo openconnect --cookie-on-stdin --protocol nc "$HOST"


Bugs
----

Due to time constraints and limited ability for testing this script
currently supports exactly one use case. Specifically, 2 factor
authentication is performed using a time-based one-time password.

Additions and modifications to expand the support are welcome.


[AUTH]: https://www.infradead.org/openconnect/manual.html#heading4
[OC]: https://www.infradead.org/openconnect/
[TNCC]: https://github.com/russdill/juniper-vpn-py
