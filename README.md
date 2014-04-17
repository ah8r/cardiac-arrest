Cardiac Arrest
==============

Hut3 Cardiac Arrest - A script to check OpenSSL servers for the Heartbleed bug (CVE-2014-0160).

Note: This code was originally a [GitHub Gist](https://gist.github.com/ah8r/10632982) but has been copied to a full [GitHub Repository](https://github.com/ah8r/cardiac-arrest) so issues can also be tracked. Both will be kept updated with the latest code revisions.

**DISCLAIMER**: There have been unconfirmed reports that this script can render HP iLO unresponsive. This script complies with the TLS specification, so responsitivity issues are likely the result of a bad implementation of TLS on the server side. CNS Hut3 and Adrian Hayter do not accept responsibility if this script crashes a server you test it against. USE IT AT YOUR OWN RISK. As always, the correct way to test for the vulnerability is to check the version of OpenSSL installed on the server in question. OpenSSL 1.0.1 through 1.0.1f are vulnerable.

This script has several advantages over similar scripts that have been released, including a larger list of supported TLS cipher suites, support for multiple TLS protocol versions (including SSLv3 since some configurations leak memory when SSLv3 is used). Multiple ports / hosts can be tested at once, and limited STARTTLS support is included.

Examples
--------
Test all SSL/TLS protocols against 192.168.0.1 on port 443 (default behaviour):

    python cardiac-arrest.py 192.168.0.1

Test all SSL/TLS protocols against 192.168.0.1 and 192.168.0.2 on ports 443 and 8443:

    python cardiac-arrest.py -p 443,8443 192.168.0.1 192.168.0.2

Test the TLSv1.2 and TLSv1.1 protocols against 192.168.0.1 using SMTP STARTTLS on port 25:

    python cardiac-arrest.py -s smtp -p 25 -V TLSv1.2,TLSv1.1 192.168.0.1

Several sections of code have been lifted from other detection scripts and modified to make them more efficient. Sources include but are likely not limited to:

* https://bitbucket.org/johannestaas/heartattack (johannestaas@gmail.com)
* https://gist.github.com/takeshixx/10107280 (takeshix@adversec.com)

Like other authors of Heartbleed scripts, I disclaim copyright to this source code.
