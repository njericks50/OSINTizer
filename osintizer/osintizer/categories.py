"""The finding groups shown in the Findings tab, in display order."""

CATEGORIES = [
    {"id": "emails",       "label": "Emails",                    "icon": "@"},
    {"id": "users",        "label": "Users & Usernames",         "icon": "U"},
    {"id": "people",       "label": "People",                    "icon": "P"},
    {"id": "accounts",     "label": "Online Accounts",           "icon": "A"},
    {"id": "domains",      "label": "Domains",                   "icon": "D"},
    {"id": "subdomains",   "label": "Subdomains",                "icon": "S"},
    {"id": "ips",          "label": "IP Addresses",              "icon": "#"},
    {"id": "dns",          "label": "DNS Records",               "icon": "R"},
    {"id": "registration", "label": "Registration / WHOIS",      "icon": "W"},
    {"id": "services",     "label": "Servers & Services",        "icon": "S"},
    {"id": "technologies", "label": "Technologies",              "icon": "T"},
    {"id": "urls",         "label": "URLs",                      "icon": "L"},
    {"id": "files",        "label": "Files & Documents",         "icon": "F"},
    {"id": "phones",       "label": "Phone Numbers",             "icon": "#"},
    {"id": "notes",        "label": "Other Notes",               "icon": "N"},
]

CATEGORY_IDS = [c["id"] for c in CATEGORIES]
LABELS = {c["id"]: c["label"] for c in CATEGORIES}
