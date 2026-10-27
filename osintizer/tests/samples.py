"""Representative tool output used by the tests (and by the demo fake tools)."""

THEHARVESTER = """
*******************************************************************
*  _   _                                            _             *
* | |_| |__   ___    /\\  /\\__ _ _ ____   _____  ___| |_ ___ _ __  *
* theHarvester 4.6.0                                              *
* Coded by Christian Martorella                                   *
* Edge-Security Research                                          *
* cmartorella@edge-security.com                                   *
*******************************************************************

[*] Target: acme-corp.com

[*] Searching CRTsh.
[*] Searching Hackertarget.

[*] ASNS found: 1
--------------------
AS13335

[*] Interesting Urls found: 2
--------------------
https://www.acme-corp.com/careers
https://docs.acme-corp.com/files/2024-annual-report.pdf

[*] LinkedIn Users found: 2
---------------------
Jane Doe - Security Engineer - Acme Corp | LinkedIn
Mark Liu - IT Director - Acme Corp

[*] IPs found: 2
-------------------
104.18.22.10
10.20.1.5

[*] Emails found: 3
----------------------
jane.doe@acme-corp.com
mliu@acme-corp.com
info@acme-corp.com

[*] Hosts found: 4
---------------------
mail.acme-corp.com:104.18.22.10
vpn.acme-corp.com:10.20.1.5
dev.acme-corp.com
acme-corp.com
"""

DIG = """
acme-corp.com.		300	IN	A	104.18.22.10
acme-corp.com.		300	IN	MX	1 aspmx.l.google.com.
acme-corp.com.		300	IN	MX	10 alt3.aspmx.l.google.com.
acme-corp.com.		86400	IN	NS	ns1.cloudflare.com.
acme-corp.com.		300	IN	TXT	"v=spf1 include:_spf.google.com include:sendgrid.net ~all"
acme-corp.com.		300	IN	TXT	"atlassian-domain-verification=abc123"
"""

WHOIS = """
   Domain Name: ACME-CORP.COM
   Registry Domain ID: 123_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.namecheap.com
   Registrar URL: http://www.namecheap.com
   Updated Date: 2025-01-10T10:00:00Z
   Creation Date: 2012-03-02T15:00:00Z
   Registry Expiry Date: 2027-03-02T15:00:00Z
   Registrar: NameCheap, Inc.
   Registrar Abuse Contact Email: abuse@namecheap.com
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Name Server: NS1.CLOUDFLARE.COM
   Name Server: NS2.CLOUDFLARE.COM
   DNSSEC: unsigned
>>> Last update of whois database: 2026-10-27T17:00:00Z <<<

NOTICE: The expiration date displayed in this record is the date the
registrar's sponsorship of the domain name registration in the registry is
currently set to expire. See https://www.verisign.com for more.
Domain Name: acme-corp.com
Registrant Organization: Acme Corporation
Registrant Name: REDACTED FOR PRIVACY
Registrant Country: US
"""

SHERLOCK = """
[*] Checking username jdoe_sec on:

[+] GitHub: https://www.github.com/jdoe_sec
[+] Reddit: https://www.reddit.com/user/jdoe_sec
[+] Keybase: https://keybase.io/jdoe_sec

[*] Search completed with 3 results
"""

HOLEHE = """
***************************
   jane.doe@acme-corp.com
***************************
[+] instagram.com
[+] spotify.com
[+] adobe.com / ja****@gmail.com
[+] Email used, [-] Email not used, [x] Rate limit, [!] Error
121 websites checked in 8.2 seconds
"""

NMAP = """
Starting Nmap 7.95 ( https://nmap.org ) at 2026-10-27 13:00 EDT
Nmap scan report for acme-corp.com (104.18.22.10)
Host is up (0.012s latency).
Not shown: 97 filtered tcp ports
PORT    STATE SERVICE  VERSION
80/tcp  open  http     cloudflare
443/tcp open  ssl/http cloudflare
8443/tcp open https-alt nginx 1.24.0
Service detection performed.
Nmap done: 1 IP address (1 host up) scanned in 20.1 seconds
"""

WHATWEB = "https://acme-corp.com [200 OK] Cloudflare, Country[UNITED STATES][US], Email[press@acme-corp.com], HTML5, HTTPServer[cloudflare], IP[104.18.22.10], JQuery[3.6.0], Title[Acme Corp - Home], WordPress[6.5.2], X-Powered-By[PHP/8.2.1]"

SUBFINDER = """
api.acme-corp.com
staging.acme-corp.com
*.cdn.acme-corp.com
shop.acme-corp.com
"""
