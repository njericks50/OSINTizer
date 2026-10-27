"""Registry of OSINT collectors that OSINTizer can launch on Kali.

Each collector is a command template. "{target}" is replaced with the target
(validated for the collector's input type). Commands are executed as an
argument list - never through a shell - so targets can't inject commands.
Users can edit the argument template per run from the UI or CLI.
"""

from __future__ import annotations

import json
import shlex
import shutil
import ssl
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field

from .extractors import detect_type


@dataclass
class Collector:
    id: str
    name: str
    inputs: list[str]                 # target types it accepts: domain, email, username, ip, cidr, url
    description: str
    binaries: list[str] = field(default_factory=list)   # first one found on PATH is used
    args: str = ""                   # default argument template
    timeout: int = 600
    install: str = ""                # how to install on Kali
    active: bool = False             # touches the target directly (not passive OSINT)
    builtin: str = ""                # name of a Python implementation instead of a binary

    def binary_path(self) -> str | None:
        for b in self.binaries:
            p = shutil.which(b)
            if p:
                return p
        return None

    def installed(self) -> bool:
        return bool(self.builtin) or self.binary_path() is not None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["installed"] = self.installed()
        d["binary"] = self.binary_path() or ""
        return d


COLLECTORS: list[Collector] = [
    Collector(
        "theharvester", "theHarvester", ["domain"],
        "Emails, subdomains, IPs, people and URLs from public search engines and datasets.",
        ["theHarvester", "theharvester"],
        "-d {target} -b crtsh,hackertarget,otx,rapiddns,urlscan -l 200",
        900, "sudo apt install theharvester",
    ),
    Collector(
        "crtsh", "crt.sh (built-in)", ["domain"],
        "Subdomains from Certificate Transparency logs. No install needed.",
        [], "{target}", 120, "built in", builtin="crtsh",
    ),
    Collector(
        "subfinder", "subfinder", ["domain"],
        "Fast passive subdomain discovery from many sources.",
        ["subfinder"], "-d {target} -silent -rl 10 -t 5", 900, "sudo apt install subfinder",
    ),
    Collector(
        "amass", "Amass (passive)", ["domain"],
        "In-depth passive attack-surface mapping (subdomains, netblocks, ASNs).",
        ["amass"], "enum -passive -d {target} -timeout 20", 1800, "sudo apt install amass",
    ),
    Collector(
        "assetfinder", "assetfinder", ["domain"],
        "Finds related domains and subdomains.",
        ["assetfinder"], "--subs-only {target}", 600, "sudo apt install assetfinder",
    ),
    Collector(
        "dig", "dig (DNS records)", ["domain"],
        "A, AAAA, MX, NS, TXT, SOA and CAA records; infers mail/DNS providers from them.",
        ["dig"],
        "+noall +answer {target} A {target} AAAA {target} MX {target} NS {target} TXT {target} SOA {target} CAA",
        60, "sudo apt install dnsutils",
    ),
    Collector(
        "whois", "whois", ["domain", "ip"],
        "Registrar, registrant org, dates, name servers, net ranges and ASNs.",
        ["whois"], "{target}", 60, "sudo apt install whois",
    ),
    Collector(
        "whatweb", "WhatWeb", ["domain", "url"],
        "Fingerprints web technologies, servers, CMS, emails and page titles.",
        ["whatweb"], "--color=never -a 1 --max-threads 1 {target}", 300, "sudo apt install whatweb", active=True,
    ),
    Collector(
        "sherlock", "Sherlock", ["username"],
        "Hunts a username across hundreds of social networks.",
        ["sherlock"], "{target} --print-found --no-color --timeout 15", 900, "sudo apt install sherlock",
    ),
    Collector(
        "maigret", "Maigret", ["username"],
        "Username dossier across thousands of sites.",
        ["maigret"], "{target} --no-color --no-progressbar --timeout 15 -n 20", 1800, "pipx install maigret",
    ),
    Collector(
        "holehe", "holehe", ["email"],
        "Checks which websites an email address is registered on.",
        ["holehe"], "{target} --only-used --no-color", 600, "pipx install holehe",
    ),
    Collector(
        "nmap", "Nmap (gentle, single host)", ["domain", "ip"],
        "Slow service scan of the top 100 ports on ONE host, rate-limited so it won't flood your "
        "router. ACTIVE - only scan hosts you're authorized to test. Network ranges are not allowed.",
        ["nmap"], "-Pn -sV -T2 --top-ports 100 --max-rate 20 --max-parallelism 5 --max-retries 1 {target}",
        1800, "sudo apt install nmap", active=True,
    ),
]

BY_ID = {c.id: c for c in COLLECTORS}


class TargetError(ValueError):
    pass


def validate_target(collector: Collector, target: str) -> str:
    target = (target or "").strip()
    if not target:
        raise TargetError("Enter a target first")
    if target.startswith("-"):
        raise TargetError("Targets can't start with '-'")
    if any(ch in target for ch in "\n\r\t\0 ;|&$`<>\"'"):
        raise TargetError("Target contains characters that aren't allowed")
    kind = detect_type(target)
    if kind not in collector.inputs:
        wanted = ", ".join(collector.inputs)
        raise TargetError(f"{collector.name} needs a {wanted} target (got {kind or 'unrecognized'})")
    if kind == "domain":
        target = target.lower().rstrip(".")
    return target


def build_argv(collector: Collector, target: str, args_template: str | None = None) -> list[str]:
    template = args_template if args_template not in (None, "") else collector.args
    if "{target}" not in template:
        template = template + " {target}"
    parts = shlex.split(template)
    argv = [p.replace("{target}", target) for p in parts]
    if collector.builtin:
        return [collector.builtin, *argv]
    binary = collector.binary_path()
    if not binary:
        raise TargetError(f"{collector.name} isn't installed. Install with: {collector.install}")
    return [binary, *argv]


def matching_collectors(target: str) -> list[Collector]:
    kind = detect_type(target)
    return [c for c in COLLECTORS if kind in c.inputs]


# ------------------------------------------------------------------ builtins
def builtin_crtsh(target: str, timeout: int = 120) -> str:
    q = urllib.parse.quote(f"%.{target}")
    url = f"https://crt.sh/?q={q}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "OSINTizer/1.0 (+https://github.com)"})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        data = json.loads(resp.read().decode("utf-8", "replace") or "[]")
    names = set()
    for row in data:
        for n in str(row.get("name_value", "")).split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n:
                names.add(n)
    lines = [f"# crt.sh certificate transparency results for {target}", f"# {len(names)} unique names", ""]
    lines += sorted(names)
    return "\n".join(lines) + "\n"


BUILTINS = {"crtsh": builtin_crtsh}
