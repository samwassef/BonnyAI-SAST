"""Bounded, literal JavaScript clue scanning for HTTP inspection.

Matches are leads for review, not proof of a vulnerability. No matched value or
surrounding source is copied into the report, so credential values stay out of it.
"""

import re
from bisect import bisect_right
from html.parser import HTMLParser
from urllib.parse import urljoin


# Keep labels fixed and patterns narrow enough to avoid treating every short word
# inside a larger identifier as a separate clue.
PATTERNS = {
    "Hidden endpoints": [r"/api/", r"/v1/", r"/v2/", r"graphql", r"\bfetch\s*\(",
                         r"\baxios\b", r"\bXMLHttpRequest\b", r"\.open\s*\("],
    "Admin/internal functions": [r"\badmin\b", r"\binternal\b", r"\bdebug\b", r"\bstaff\b",
                                 r"\bsuperuser\b", r"\bmoderator\b", r"\bimpersonate\b"],
    "Secrets": [r"\bapiKey\b", r"\bapi_key\b", r"\bsecret\b", r"\btoken\b",
                r"\bpassword\b", r"\bclientSecret\b", r"\bAuthorization\b"],
    "Cloud credentials/config": [r"\bAWS_", r"\bAKIA[A-Z0-9]*", r"\bfirebase\b",
                                 r"\bstorageAccount\b", r"\bsasToken\b", r"\bclient_id\b"],
    "Source maps": [r"sourceMappingURL", r"\.js\.map\b"],
    "Dev/test environments": [r"\bdev\.", r"\bqa\.", r"\bstage\.", r"\bstaging\.",
                              r"\blocalhost\b", r"\b127\.0\.0\.1\b"],
    "Feature flags": [r"\bfeatureFlag\b", r"\benableAdmin\b", r"\bbeta\b", r"\bexperimental\b"],
    "Authorization logic": [r"\brole\b", r"\bpermission\b", r"\bisAdmin\b", r"\buserId\b",
                            r"\baccountId\b", r"\btenantId\b"],
    "DOM XSS sources": [r"location\.search", r"location\.hash", r"document\.URL",
                        r"document\.referrer", r"window\.name", r"\blocalStorage\b"],
    "DOM XSS sinks": [r"\binnerHTML\b", r"\bouterHTML\b", r"document\.write\s*\(",
                      r"\beval\s*\(", r"\bFunction\s*\(", r"\binsertAdjacentHTML\s*\("],
    "Redirects": [r"window\.location", r"location\.href", r"location\.assign\s*\(",
                  r"location\.replace\s*\("],
    "Dynamic resources": [r"\.src\s*=", r"\.href\s*=", r"createElement\s*\(\s*['\"]script['\"]\s*\)"],
    "Web messaging": [r"\bpostMessage\s*\(", r"addEventListener\s*\(\s*['\"]message['\"]"],
    "WebSockets": [r"\bWebSocket\s*\(", r"wss://", r"ws://"],
    "Storage": [r"\blocalStorage\b", r"\bsessionStorage\b", r"\bIndexedDB\b"],
    "CORS clues": [r"credentials\s*:\s*['\"]include['\"]", r"\bwithCredentials\b"],
    "GraphQL": [r"/graphql", r"\bmutation\b", r"\bquery\b", r"\b__typename\b"],
    "File upload": [r"\bFormData\b", r"\bmultipart\b", r"\bFileReader\b", r"\baccept\s*="],
    "Prototype manipulation": [r"__proto__", r"\bconstructor\b", r"\bprototype\b",
                               r"Object\.assign\s*\("],
    "Dangerous JS execution": [r"\beval\s*\(", r"\bFunction\s*\(",
                               r"setTimeout\s*\(\s*['\"]", r"setInterval\s*\(\s*['\"]"],
    "Interesting comments": [r"\bTODO\b", r"\bFIXME\b", r"\bHACK\b", r"\btemporary\b",
                             r"remove before prod"],
}


class ScriptTags(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.sources = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            source = dict(attrs).get("src")
            if source:
                self.sources.append(source)


def script_urls(html: str, page_url: str) -> list[str]:
    parser = ScriptTags()
    parser.feed(html)
    return list(dict.fromkeys(urljoin(page_url, source) for source in parser.sources))


def scan_js(source: str) -> list[dict]:
    newline_positions = [match.start() for match in re.finditer("\n", source)]
    comments = [(m.start(), m.group()) for m in re.finditer(r"//[^\n]*|/\*[\s\S]*?\*/", source)]
    results = []
    for category, patterns in PATTERNS.items():
        for pattern in patterns:
            label = (pattern.replace(r"\b", "").replace(r"\s*", "")
                     .replace(r"\.", ".").replace(r"\(", "(")
                     .replace(r"['\"]", '"').replace("[A-Z0-9]*", ""))
            positions = []
            if category == "Interesting comments":
                for offset, comment in comments:
                    positions.extend(offset + match.start() for match in re.finditer(pattern, comment, re.I))
            else:
                positions = [match.start() for match in re.finditer(pattern, source, re.I)]
            if positions:
                results.append({"category": category, "term": label,
                                "count": len(positions),
                                "lines": sorted(set(bisect_right(newline_positions, pos) + 1
                                                    for pos in positions))[:5]})
    return results
