"""Turn raw tool output into grouped findings.

Every collector's output goes through two passes:

1. A tool-aware parser (theHarvester sections, dig answers, whois fields,
   sherlock/holehe hits, whatweb plugins, nmap ports ...) that understands
   context a regex can't see.
2. A generic extractor (emails, hosts, IPs, URLs, social profiles, phones)
   that runs on everything the tool parser didn't fully consume.

Results are dicts: {"category", "value", "detail", "in_scope"}.
"""

from __future__ import annotations

import ipaddress
import os
import re
from functools import lru_cache
from urllib.parse import urlsplit

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07")

EMAIL_RE = re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}(?![\w-])")
HOST_RE = re.compile(r"(?<![\w@.-])(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\.?(?![\w@-])")
IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:/(?:3[0-2]|[12]?\d))?(?![\d]|\.\d)")
IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?(?![\w:])")
URL_RE = re.compile(r"\bhttps?://[^\s<>\"'`\\]+", re.I)
PHONE_RES = [
    re.compile(r"(?<![\w.+])\+\d{1,3}[ .-]?\(?\d{1,4}\)?(?:[ .-]?\d{2,4}){2,4}(?![\w])"),
    re.compile(r"(?<![\w.+-])\(\d{3}\)\s?\d{3}[ .-]\d{4}(?![\w])"),
    re.compile(r"(?<![\w.+-])\d{3}[.-]\d{3}[.-]\d{4}(?![\w.-])"),
]
ASN_RE = re.compile(r"\bAS(\d{1,10})\b")

# File extensions that are also real TLDs: only trust them for in-scope hosts
# or hosts with 3+ labels, so "results.sh" or "run.py" aren't reported as domains.
AMBIGUOUS_TLDS = {"py", "sh", "pl", "md", "rs", "so", "ps", "zip", "mov", "pm", "ml", "tf", "sc", "ws", "nu"}

IMAGE_EXT = {"png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "css", "js"}

DOC_EXT = {
    "pdf", "doc", "docx", "xls", "xlsx", "xlsm", "ppt", "pptx", "odt", "ods", "odp", "rtf",
    "csv", "txt", "zip", "rar", "7z", "tar", "gz", "bak", "sql", "db", "log", "conf", "config",
    "env", "ini", "yml", "yaml", "json", "xml", "key", "pem", "pfx", "ps1", "bat", "sh",
}

ROLE_LOCALPARTS = {
    "info", "admin", "administrator", "contact", "support", "help", "sales", "office",
    "hello", "noreply", "no-reply", "donotreply", "do-not-reply", "webmaster", "postmaster",
    "hostmaster", "abuse", "security", "privacy", "legal", "marketing", "billing", "jobs",
    "careers", "hr", "press", "media", "news", "newsletter", "team", "service", "enquiries",
    "inquiries", "feedback", "mail", "email", "root", "test", "user", "example", "accounts",
}

# Hosts/emails printed by the tools themselves (banners, credits) - never findings.
IGNORE_HOSTS = {"edge-security.com", "www.edge-security.com", "localhost", "localhost.localdomain"}
IGNORE_EMAILS = {"cmartorella@edge-security.com"}

SOCIAL_PATTERNS = [
    (r"(?:twitter|x)\.com/(?!(?:home|share|intent|search|hashtag|i|login|signup|explore|settings|privacy|tos)\b)@?([A-Za-z0-9_]{1,15})\b", "X / Twitter"),
    (r"instagram\.com/(?!(?:p|explore|reel|reels|accounts|stories|about|developer)\b)([A-Za-z0-9_.]{1,30})", "Instagram"),
    (r"facebook\.com/(?!(?:sharer|share|pages|groups|events|login|profile\.php|watch|policies|help|dialog|tr|plugins)\b)([A-Za-z0-9.]{3,50})", "Facebook"),
    (r"linkedin\.com/in/([A-Za-z0-9_%-]{2,100})", "LinkedIn"),
    (r"linkedin\.com/company/([A-Za-z0-9_%-]{2,100})", "LinkedIn Company"),
    (r"github\.com/(?!(?:features|about|login|join|orgs|topics|sponsors|marketplace|pricing|site|security|enterprise|collections|settings|explore|trending|search|apps|contact)\b)([A-Za-z0-9-]{1,39})", "GitHub"),
    (r"gitlab\.com/(?!(?:explore|users/sign_in|help)\b)([A-Za-z0-9_.-]{2,255})", "GitLab"),
    (r"reddit\.com/(?:u|user)/([A-Za-z0-9_-]{3,20})", "Reddit"),
    (r"tiktok\.com/@([A-Za-z0-9_.]{2,24})", "TikTok"),
    (r"youtube\.com/(?:@|c/|user/)([A-Za-z0-9_.-]{3,100})", "YouTube"),
    (r"medium\.com/@([A-Za-z0-9_.-]{1,30})", "Medium"),
    (r"(?<![\w.])t\.me/([A-Za-z0-9_]{5,32})", "Telegram"),
    (r"pinterest\.[a-z.]+/([A-Za-z0-9_]{3,30})/?$", "Pinterest"),
    (r"keybase\.io/([A-Za-z0-9_]{2,16})", "Keybase"),
    (r"twitch\.tv/([A-Za-z0-9_]{4,25})", "Twitch"),
    (r"threads\.net/@([A-Za-z0-9_.]{1,30})", "Threads"),
    (r"bsky\.app/profile/([A-Za-z0-9_.-]{3,253})", "Bluesky"),
    (r"(?:www\.)?hackerone\.com/([A-Za-z0-9_-]{2,40})$", "HackerOne"),
]
SOCIAL_RES = [(re.compile(p, re.I), name) for p, name in SOCIAL_PATTERNS]

# Infer services/vendors from DNS records - cheap and very useful recon.
TECH_HINTS = [
    (r"aspmx\.l\.google\.com|_spf\.google\.com|googlemail\.com", "Google Workspace (email)"),
    (r"google-site-verification", "Google Search Console (verified)"),
    (r"protection\.outlook\.com|spf\.protection\.outlook|^ms=ms\d+|\bMS=ms\d+", "Microsoft 365"),
    (r"pphosted\.com", "Proofpoint (email security)"),
    (r"mimecast", "Mimecast (email security)"),
    (r"barracudanetworks", "Barracuda (email security)"),
    (r"sendgrid\.net", "SendGrid"),
    (r"mailgun\.org", "Mailgun"),
    (r"amazonses\.com", "Amazon SES"),
    (r"mcsv\.net|mailchimp", "Mailchimp"),
    (r"zendesk", "Zendesk"),
    (r"salesforce\.com|_spf\.salesforce", "Salesforce"),
    (r"hubspot", "HubSpot"),
    (r"zoho", "Zoho"),
    (r"facebook-domain-verification", "Facebook / Meta Business"),
    (r"atlassian-domain-verification", "Atlassian"),
    (r"docusign", "DocuSign"),
    (r"apple-domain-verification", "Apple"),
    (r"stripe-verification", "Stripe"),
    (r"adobe-idp-site-verification|adobe-sign-verification", "Adobe"),
    (r"slack-domain-verification", "Slack"),
    (r"dropbox-domain-verification", "Dropbox"),
    (r"onetrust-domain-verification", "OneTrust"),
    (r"cloudflare\.com\.?$|ns\.cloudflare\.com", "Cloudflare DNS"),
    (r"awsdns", "AWS Route 53"),
    (r"azure-dns", "Azure DNS"),
    (r"domaincontrol\.com", "GoDaddy DNS"),
    (r"registrar-servers\.com", "Namecheap DNS"),
    (r"nsone\.net", "NS1 DNS"),
    (r"akam\.net|akamai", "Akamai"),
    (r"cloudfront\.net", "AWS CloudFront"),
    (r"azurewebsites\.net|cloudapp\.net", "Microsoft Azure hosting"),
    (r"herokuapp\.com|herokudns", "Heroku"),
    (r"github\.io", "GitHub Pages"),
    (r"wpengine", "WP Engine"),
    (r"shopify", "Shopify"),
    (r"squarespace", "Squarespace"),
    (r"wixdns|wix\.com", "Wix"),
]
TECH_RES = [(re.compile(p, re.I), name) for p, name in TECH_HINTS]


# --------------------------------------------------------------------------
# Public suffix handling (uses Kali's publicsuffix package when present)
# --------------------------------------------------------------------------
_CCTLDS = (
    "ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw by bz "
    "ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk "
    "fm fo fr ga gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir "
    "is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh mk "
    "ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl "
    "pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st su sv sx sy sz tc "
    "td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw"
)
_GTLDS = (
    "com net org edu gov mil int info biz name pro aero coop museum mobi asia tel travel jobs cat xyz online "
    "site top club shop store tech app dev cloud blog news live life world today space website fun agency "
    "email digital network solutions services systems company group media studio design global security link "
    "click page host zone center inc llc ltd academy bank finance capital consulting health law legal "
    "marketing software support university school church foundation institute io ai co me tv us uk ca de eu "
    "one art work social tools team expert energy events games guru money photo photography pics plus rocks "
    "run science shopping solar tips town toys training video vip wiki win works xxx gay lgbt ngo ong onion "
    "google amazon microsoft apple aws azure gle goog youtube windows office"
)
PSL_PATHS = [
    "/usr/share/publicsuffix/public_suffix_list.dat",
    "/usr/share/publicsuffix/effective_tld_names.dat",
]


@lru_cache(maxsize=1)
def _psl():
    rules, wild, exc = set(), set(), set()
    for path in PSL_PATHS:
        if os.path.exists(path):
            with open(path, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip().lower()
                    if not line or line.startswith("//"):
                        continue
                    line = line.split()[0]
                    try:
                        line = line.encode("idna").decode("ascii") if not line.isascii() else line
                    except Exception:
                        continue
                    if line.startswith("!"):
                        exc.add(line[1:])
                    elif line.startswith("*."):
                        wild.add(line[2:])
                    else:
                        rules.add(line)
            break
    if not rules:
        rules = set(_CCTLDS.split()) | set(_GTLDS.split())
        for cc in ("uk", "au", "nz", "za", "jp", "br", "in", "il", "kr", "tr", "mx", "ar", "cn", "tw", "sg", "my", "id", "th", "ph", "pk", "ng", "eg"):
            for sl in ("co", "com", "org", "net", "gov", "ac", "edu"):
                rules.add(f"{sl}.{cc}")
    tlds = {r.rsplit(".", 1)[-1] for r in rules}
    return rules, wild, exc, tlds


def valid_tld(tld: str) -> bool:
    return tld.lower() in _psl()[3]


def registrable_domain(host: str) -> str:
    host = host.lower().rstrip(".")
    labels = host.split(".")
    rules, wild, exc, _ = _psl()
    for i in range(len(labels)):
        suffix = ".".join(labels[i:])
        if suffix in exc:
            return suffix
        parent = ".".join(labels[i + 1:])
        if suffix in rules or (parent and parent in wild):
            return ".".join(labels[i - 1:]) if i > 0 else host
    return ".".join(labels[-2:])


SCOPED_CATEGORIES = {"domains", "subdomains", "emails", "urls", "files"}


def in_scope(category: str, value: str, scope) -> bool:
    """Only host-bearing groups can be out of scope; people, IPs, users etc. always show."""
    if not scope or category not in SCOPED_CATEGORIES:
        return True
    host = value.lower()
    if category == "emails":
        host = host.rsplit("@", 1)[-1]
    elif category in ("urls", "files", "accounts"):
        host = (urlsplit(value).hostname or "").lower()
    host = host.rstrip(".")
    return any(host == d or host.endswith("." + d) for d in scope)


# --------------------------------------------------------------------------
# Target detection / validation (used by collectors)
# --------------------------------------------------------------------------
DOMAIN_FULL_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}$")
EMAIL_FULL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}$")
USERNAME_FULL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def detect_type(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if t.lower().startswith(("http://", "https://")):
        return "url"
    if EMAIL_FULL_RE.match(t):
        return "email"
    try:
        ipaddress.ip_address(t)
        return "ip"
    except ValueError:
        pass
    try:
        if "/" in t:
            ipaddress.ip_network(t, strict=False)
            return "cidr"
    except ValueError:
        pass
    if DOMAIN_FULL_RE.match(t) and valid_tld(t.rsplit(".", 1)[-1]):
        return "domain"
    if USERNAME_FULL_RE.match(t):
        return "username"
    return ""


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text or "").replace("\r\n", "\n").replace("\r", "\n")


def _clean_url(u: str) -> str:
    u = u.rstrip(".,;:!?)]}'\"")
    if u.count("(") < u.count(")"):
        u = u.rstrip(")")
    return u


def _f(category, value, detail="", scope=None):
    return {"category": category, "value": value, "detail": detail,
            "in_scope": in_scope(category, value, scope or [])}


def _host_ok(host: str, scope) -> bool:
    labels = host.split(".")
    if len(labels) < 2 or host in IGNORE_HOSTS:
        return False
    tld = labels[-1]
    if not valid_tld(tld) or tld.isdigit():
        return False
    if tld in AMBIGUOUS_TLDS and len(labels) < 3 and not (scope and in_scope("domains", host, scope)):
        return False
    if any(len(l) == 0 or len(l) > 63 for l in labels):
        return False
    return True


def classify_host(host: str, scope, detail="") -> dict | None:
    host = host.lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    if not _host_ok(host, scope):
        return None
    if scope and in_scope("domains", host, scope):
        root = host in scope
    else:
        root = registrable_domain(host) == host
    cat = "domains" if root else "subdomains"
    return _f(cat, host, detail, scope)


def tech_from(text: str, detail: str, scope):
    out = []
    for rx, name in TECH_RES:
        if rx.search(text):
            out.append(_f("technologies", name, detail, scope))
    return out


# --------------------------------------------------------------------------
# Generic extraction
# --------------------------------------------------------------------------
def extract_generic(text: str, scope=None, tool: str = "") -> list[dict]:
    scope = scope or []
    out: list[dict] = []
    text = text.replace("*.", "")  # wildcard hosts from cert logs / subfinder

    url_spans = []
    for m in URL_RE.finditer(text):
        url = _clean_url(m.group(0))
        url_spans.append((m.start(), m.start() + len(url)))
        out.extend(classify_url(url, scope))

    for m in EMAIL_RE.finditer(text):
        email = m.group(0).lower().strip(".")
        domain = email.rsplit("@", 1)[1]
        tld = domain.rsplit(".", 1)[-1]
        if email in IGNORE_EMAILS or tld in IMAGE_EXT or not valid_tld(tld):
            continue
        out.append(_f("emails", email, "", scope))
        h = classify_host(domain, scope, "email domain")
        if h:
            out.append(h)
        local = email.split("@", 1)[0].split("+", 1)[0]
        if local not in ROLE_LOCALPARTS and len(local) >= 3 and not local.isdigit():
            out.append(_f("users", local, f"from {email}", scope))

    for m in HOST_RE.finditer(text):
        start = m.start()
        host = m.group(0)
        # Skip things like "file.txt" written directly after a slash in a path.
        if start > 0 and text[start - 1] in "/\\" and not any(a <= start < b for a, b in url_spans):
            continue
        h = classify_host(host, scope)
        if h:
            out.append(h)

    for m in IPV4_RE.finditer(text):
        out.extend(classify_ip(m.group(0), scope))

    for m in IPV6_RE.finditer(text):
        cand = m.group(0)
        if cand.count(":") < 2:
            continue
        try:
            if "/" in cand:
                ipaddress.ip_network(cand, strict=False)
            else:
                ipaddress.IPv6Address(cand)
        except ValueError:
            continue
        out.extend(classify_ip(cand, scope))

    if tool not in ("nmap", "dig", "dnsrecon"):
        for rx in PHONE_RES:
            for m in rx.finditer(text):
                digits = re.sub(r"\D", "", m.group(0))
                if 7 <= len(digits) <= 15 and not re.fullmatch(r"(\d)\1+", digits):
                    out.append(_f("phones", m.group(0).strip(), "", scope))

    if tool in ("amass", "theharvester", "whois", "paste"):
        for m in ASN_RE.finditer(text):
            out.append(_f("registration", f"ASN: AS{m.group(1)}", "", scope))

    return out


def classify_ip(raw: str, scope) -> list[dict]:
    try:
        if "/" in raw:
            net = ipaddress.ip_network(raw, strict=False)
            if net.prefixlen == net.max_prefixlen:
                raw = str(net.network_address)
            else:
                return [_f("ips", str(net), "network range", scope)]
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return []
    if ip.is_unspecified or str(ip) in ("255.255.255.255",) or ip.is_multicast:
        return []
    detail = ""
    if ip.is_loopback:
        return []
    if ip.is_private:
        detail = "private"
    elif ip.is_reserved or ip.is_link_local:
        detail = "reserved"
    return [_f("ips", str(ip), detail, scope)]


def classify_url(url: str, scope) -> list[dict]:
    out = []
    try:
        parts = urlsplit(url)
    except ValueError:
        return out
    host = (parts.hostname or "").lower()
    if not host or host in IGNORE_HOSTS:
        return out
    path = parts.path or ""
    ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
    if ext in DOC_EXT:
        out.append(_f("files", url, ext.upper(), scope))
    else:
        matched = False
        for rx, platform in SOCIAL_RES:
            m = rx.search(host + path)
            if m:
                handle = m.group(1).strip("/")
                if not handle:
                    continue
                matched = True
                base = f"{parts.scheme}://{host}{path}".rstrip("/")
                out.append(_f("accounts", base, platform, scope))
                if platform not in ("LinkedIn Company",):
                    out.append(_f("users", handle.lstrip("@"), platform, scope))
                break
        if not matched:
            out.append(_f("urls", url, "", scope))
    h = classify_host(host, scope, "")
    if h:
        out.append(h)
    return out


# --------------------------------------------------------------------------
# Tool-aware parsers. Each returns (findings, set_of_line_numbers_consumed)
# --------------------------------------------------------------------------
def parse_theharvester(lines, scope, target):
    out, used = [], set()
    section = None
    for i, raw in enumerate(lines):
        line = raw.strip()
        head = re.match(r"^\[\*\]\s*(.+?)(?:\s+found)?\s*:\s*(\d*)\s*$", line, re.I)
        if head:
            section = head.group(1).lower()
            used.add(i)
            continue
        if not line or set(line) <= set("-=*"):
            continue
        if line.startswith("[") and not line.startswith("[*]"):
            continue
        if section is None:
            continue
        if any(k in section for k in ("linkedin", "people", "users", "names")) and "twitter" not in section:
            name = re.split(r"\s[-|–]\s", line)[0].strip()
            if re.fullmatch(r"[A-Za-zÀ-ÿ'’.\- ]{3,80}", name) and 1 < len(name.split()) <= 6:
                out.append(_f("people", name, "theHarvester (" + section + ")", scope))
                used.add(i)
            elif USERNAME_FULL_RE.match(line):
                out.append(_f("users", line, "theHarvester", scope))
                used.add(i)
        elif "twitter" in section:
            handle = line.lstrip("@").split()[0]
            if USERNAME_FULL_RE.match(handle):
                out.append(_f("users", handle, "X / Twitter (theHarvester)", scope))
                out.append(_f("accounts", f"https://x.com/{handle}", "X / Twitter", scope))
                used.add(i)
        elif "asn" in section:
            m = ASN_RE.search(line)
            if m:
                out.append(_f("registration", f"ASN: AS{m.group(1)}", "theHarvester", scope))
                used.add(i)
        elif "host" in section:
            m = re.match(r"^([A-Za-z0-9_.*-]+)\s*:\s*([0-9a-fA-F:., ]+)$", line)
            if m:
                h = classify_host(m.group(1), scope, f"resolves to {m.group(2).strip()}")
                if h:
                    out.append(h)
                for ip in re.split(r"[,\s]+", m.group(2)):
                    for x in classify_ip(ip.strip(), scope):
                        x["detail"] = (x["detail"] + "; " if x["detail"] else "") + m.group(1).lower()
                        out.append(x)
                used.add(i)
    return out, used


DNS_LINE_RE = re.compile(r"^(\S+?)\.?\s+(\d+)\s+(?:IN\s+)?(A|AAAA|MX|NS|TXT|CNAME|SOA|CAA|SRV|PTR|SPF|DNSKEY|DS)\s+(.+)$", re.I)


def _dns_record(name, rtype, data, scope, src):
    out = []
    rtype = rtype.upper()
    name = name.lower().rstrip(".")
    data = data.strip()
    if rtype == "TXT":
        data = " ".join(re.findall(r'"([^"]*)"', data)) or data
        out.append(_f("dns", f"TXT {data}"[:600], name, scope))
        out.extend(tech_from(data, f"TXT on {name}", scope))
        for inc in re.findall(r"include:([A-Za-z0-9_.-]+)", data):
            h = classify_host(inc, scope, f"SPF include on {name}")
            if h:
                out.append(h)
        return out
    clean = data.rstrip(".").lower()
    out.append(_f("dns", f"{rtype} {clean}", name, scope))
    if rtype in ("A", "AAAA"):
        for x in classify_ip(clean, scope):
            x["detail"] = (x["detail"] + "; " if x["detail"] else "") + name
            out.append(x)
        h = classify_host(name, scope, f"resolves to {clean}")
        if h:
            out.append(h)
    elif rtype in ("MX", "NS", "CNAME", "PTR", "SRV", "SOA"):
        host = clean.split()[-1] if rtype in ("MX", "SRV") else clean.split()[0]
        h = classify_host(host, scope, f"{rtype} of {name}")
        if h:
            out.append(h)
        out.extend(tech_from(clean, f"{rtype} of {name}", scope))
    return out


def parse_dig(lines, scope, target):
    out, used = [], set()
    for i, raw in enumerate(lines):
        line = raw.strip()
        if not line or line.startswith(";"):
            used.add(i)
            continue
        m = DNS_LINE_RE.match(line)
        if m:
            out.extend(_dns_record(m.group(1), m.group(3), m.group(4), scope, "dig"))
            used.add(i)
    return out, used


def parse_dnsrecon(lines, scope, target):
    out, used = [], set()
    rx = re.compile(r"^\[[*+]\]\s+(A|AAAA|MX|NS|SOA|TXT|SRV|CNAME|PTR|SPF)\s+(\S+)\s*(.*)$", re.I)
    for i, raw in enumerate(lines):
        m = rx.match(raw.strip())
        if not m:
            continue
        rtype, name, rest = m.group(1).upper(), m.group(2), m.group(3).strip()
        if rtype in ("TXT", "SPF"):
            out.extend(_dns_record(name, "TXT", rest, scope, "dnsrecon"))
        elif rtype in ("A", "AAAA", "PTR"):
            out.extend(_dns_record(name, rtype, rest or name, scope, "dnsrecon"))
        else:
            # "NS ns1.example.com 1.2.3.4" -> record + host IP
            rec_host = name
            out.extend(_dns_record(target or rec_host, rtype, rec_host, scope, "dnsrecon"))
            for x in classify_ip(rest.split()[0], scope) if rest else []:
                x["detail"] = rec_host.lower()
                out.append(x)
        used.add(i)
    return out, used


WHOIS_KEYS = {
    "registrar": "Registrar",
    "sponsoring registrar": "Registrar",
    "registrant organization": "Registrant Org",
    "registrant organisation": "Registrant Org",
    "registrant name": "Registrant Name",
    "registrant country": "Registrant Country",
    "registrant state/province": "Registrant State",
    "registrant city": "Registrant City",
    "admin organization": "Admin Org",
    "tech organization": "Tech Org",
    "creation date": "Created",
    "created": "Created",
    "registered on": "Created",
    "updated date": "Updated",
    "last updated": "Updated",
    "registry expiry date": "Expires",
    "registrar registration expiration date": "Expires",
    "expiry date": "Expires",
    "expiration date": "Expires",
    "dnssec": "DNSSEC",
    "domain status": "Status",
    "orgname": "Org",
    "org-name": "Org",
    "organization": "Org",
    "organisation": "Org",
    "netrange": "Net Range",
    "inetnum": "Net Range",
    "cidr": "CIDR",
    "netname": "Net Name",
    "originas": "ASN",
    "origin": "ASN",
    "country": "Country",
    "descr": "Description",
    "abuse-mailbox": "Abuse Contact",
}
REDACTED_RE = re.compile(r"redacted|privacy|not disclosed|withheld|data protected|gdpr|statutory masking", re.I)


def parse_whois(lines, scope, target):
    out, used = [], set()
    seen_status = 0
    legalese = False
    for i, raw in enumerate(lines):
        line = raw.strip()
        if re.match(r"^(Domain Name|NetRange|inetnum|Registrar)\s*:", line, re.I):
            legalese = False
        if line.startswith((">>> Last update", "NOTICE:", "TERMS OF USE", "The Registry database")):
            legalese = True
        if legalese or line.startswith(("%", "#", ">>>", "URL of the ICANN", "For more information")):
            used.add(i)
            continue
        if not line:
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key_l, val = key.strip().lower(), val.strip()
        if not val:
            continue
        if key_l in ("name server", "nserver", "nameserver", "name servers"):
            host = val.split()[0]
            out.extend(_dns_record(target or "", "NS", host, scope, "whois"))
            used.add(i)
            continue
        label = WHOIS_KEYS.get(key_l)
        if not label:
            continue
        if label == "Status":
            used.add(i)
            seen_status += 1
            val = val.split()[0]
            if seen_status > 6:
                continue
        if label in ("Registrant Name", "Registrant Org") and REDACTED_RE.search(val):
            out.append(_f("registration", f"{label}: (redacted / privacy protected)", "whois", scope))
            used.add(i)
            continue
        out.append(_f("registration", f"{label}: {val}"[:300], "whois", scope))
        if label == "Registrant Name":
            out.append(_f("people", val, "WHOIS registrant", scope))
        # leave the line to the generic pass when it may hold emails/phones/urls
        if not re.search(r"@|https?://|\+\d", val):
            used.add(i)
    return out, used


def parse_sherlock(lines, scope, target):
    out, used = [], set()
    hits = 0
    rx = re.compile(r"^\[\+\]\s*([^:]+?):\s*(https?://\S+)")
    for i, raw in enumerate(lines):
        m = rx.match(raw.strip())
        if m:
            site, url = m.group(1).strip(), _clean_url(m.group(2))
            out.append(_f("accounts", url, site, scope))
            hits += 1
            used.add(i)
        elif raw.strip().startswith(("[-]", "[!]", "[*]")):
            used.add(i)
    if target and hits:
        out.append(_f("users", target, f"exists on {hits} site(s)", scope))
    return out, used


def parse_holehe(lines, scope, target):
    out, used = [], set()
    hits = 0
    for i, raw in enumerate(lines):
        line = raw.strip()
        m = re.match(r"^\[\+\]\s+([A-Za-z0-9.-]+\.[A-Za-z]{2,})(.*)$", line)
        if m:
            site, rest = m.group(1).lower(), m.group(2).strip(" /")
            label = f"{site} — {target}" if target else site
            out.append(_f("accounts", label, "email registered" + (f" ({rest})" if rest else ""), scope))
            hits += 1
            used.add(i)
        elif line.startswith(("[-]", "[x]", "[!]")) or "Email used" in line or "websites checked" in line:
            used.add(i)
    if target and EMAIL_FULL_RE.match(target):
        out.append(_f("emails", target.lower(), f"registered on {hits} site(s)" if hits else "checked by holehe", scope))
    return out, used


WHATWEB_SKIP = {"UncommonHeaders", "Cookies", "HttpOnly", "X-Frame-Options", "X-XSS-Protection",
                "Strict-Transport-Security", "X-UA-Compatible", "HTML5", "Script", "Meta-Author",
                "Content-Security-Policy", "Access-Control-Allow-Methods", "RedirectLocation", "IP",
                "Country", "Email", "Via-Proxy", "X-Powered-By"}


def _split_top(s):
    parts, depth, cur = [], 0, ""
    for ch in s:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts


def parse_whatweb(lines, scope, target):
    out, used = [], set()
    for raw in lines:
        m = re.match(r"^(https?://\S+)\s+\[([^\]]+)\]\s*(.*)$", raw.strip())
        if not m:
            continue
        url, status, rest = m.group(1), m.group(2), m.group(3)
        for tok in _split_top(rest):
            name = tok.split("[", 1)[0].strip()
            vals = re.findall(r"\[([^\]]*)\]", tok)
            if not name:
                continue
            if name == "Title" and vals:
                out.append(_f("notes", f"Page title: {vals[0]}", url, scope))
                continue
            if name == "X-Powered-By" and vals:
                out.append(_f("technologies", vals[0], f"X-Powered-By on {url}", scope))
                continue
            if name == "Meta-Author" and vals:
                out.append(_f("people", vals[0], f"meta author on {url}", scope))
                continue
            if name in WHATWEB_SKIP:
                continue
            value = f"{name} {vals[0]}".strip() if vals and len(vals[0]) < 80 else name
            out.append(_f("technologies", value, url, scope))
        # whatweb lines also hold emails/IPs, so let the generic pass see them too
    return out, used


def parse_nmap(lines, scope, target):
    out, used = [], set()
    host = target or ""
    for i, raw in enumerate(lines):
        line = raw.strip()
        m = re.match(r"^Nmap scan report for (\S+)(?: \(([^)]+)\))?", line)
        if m:
            host = m.group(1)
            used.add(i)
            continue
        m = re.match(r"^(\d+)/(tcp|udp)\s+(open|open\|filtered)\s+(\S+)\s*(.*)$", line)
        if m:
            port, proto, state, svc, ver = m.groups()
            value = f"{host} {port}/{proto} {svc}" + (f" — {ver.strip()}" if ver.strip() else "")
            out.append(_f("services", value, state, scope))
            if ver.strip():
                out.append(_f("technologies", ver.strip()[:120], f"{host}:{port}", scope))
            used.add(i)
            continue
        m = re.match(r"^Service Info:\s*(.+)$", line)
        if m:
            out.append(_f("technologies", m.group(1).strip(), host, scope))
            used.add(i)
        elif line.startswith(("Starting Nmap", "Nmap done", "Host is up", "Not shown", "PORT ", "Service detection", "Read data files")):
            used.add(i)
    return out, used


def parse_crtsh(lines, scope, target):
    return [], set()


PARSERS = {
    "theharvester": parse_theharvester,
    "dig": parse_dig,
    "dnsrecon": parse_dnsrecon,
    "whois": parse_whois,
    "sherlock": parse_sherlock,
    "maigret": parse_sherlock,
    "holehe": parse_holehe,
    "whatweb": parse_whatweb,
    "nmap": parse_nmap,
}


def guess_tool(text: str) -> str:
    t = text[:20000]
    checks = [
        ("nmap", r"Nmap scan report for|Starting Nmap"),
        ("theharvester", r"theHarvester|\[\*\] Target:|Hosts found:"),
        ("sherlock", r"\[\*\] Checking username|sherlock"),
        ("maigret", r"maigret|Checking username .* on:"),
        ("holehe", r"Email used, \[-\] Email not used|holehe"),
        ("dnsrecon", r"\[\*\] std: Performing General Enumeration|dnsrecon"),
        ("dig", r"<<>> DiG|^\S+\.\s+\d+\s+IN\s+[A-Z]+\s", ),
        ("whois", r"(?im)^\s*(Domain Name|Registrar|NetRange|inetnum)\s*:"),
        ("whatweb", r"(?m)^https?://\S+ \[\d{3} [^\]]*\]"),
    ]
    for tool, pat in checks:
        if re.search(pat, t, re.M | re.I):
            return tool
    return "paste"


def extract(text: str, tool: str = "", target: str = "", scope=None) -> list[dict]:
    """Main entry point: returns de-duplicated findings for one piece of output."""
    scope = [d for d in (scope or []) if d]
    text = strip_ansi(text)
    tool = (tool or "").lower()
    if tool in ("", "auto", "paste", "manual"):
        tool = guess_tool(text)
    lines = text.split("\n")
    findings, used = [], set()
    parser = PARSERS.get(tool)
    if parser:
        try:
            findings, used = parser(lines, scope, target)
        except Exception:  # a parser bug must never lose the generic pass
            findings, used = [], set()
    remaining = "\n".join(l for i, l in enumerate(lines) if i not in used)
    findings.extend(extract_generic(remaining, scope, tool))

    # Collapse duplicates, merging their details.
    merged: dict[tuple, dict] = {}
    for f in findings:
        key = (f["category"], f["value"].lower())
        if key in merged:
            d = f.get("detail") or ""
            if d and d.lower() not in merged[key]["detail"].lower():
                merged[key]["detail"] = (merged[key]["detail"] + "; " + d).strip("; ")
        else:
            merged[key] = dict(f)
    return list(merged.values())
