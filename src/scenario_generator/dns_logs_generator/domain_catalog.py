from __future__ import annotations

from random import Random


DOMAIN_CATEGORIES: dict[str, str] = {
    "login.contoso.com": "business",
    "portal.contoso.com": "business",
    "www.office.com": "business",
    "api.salesforce.com": "saas",
    "github.com": "developer",
    "cdn.example.net": "cloud",
    "drive.microsoft.com": "cloud",
    "update.windows.com": "system",
    "teams.microsoft.com": "business",
    "outlook.office.com": "business",
    "sharepoint.com": "business",
    "app.powerbi.com": "business",
    "docs.microsoft.com": "developer",
    "www.google.com": "web",
    "www.bing.com": "search",
    "www.linkedin.com": "social",
    "www.netflix.com": "streaming",
    "api.github.com": "developer",
    "raw.githubusercontent.com": "developer",
    "pypi.org": "developer",
    "www.npmjs.com": "developer",
    "www.amazon.com": "shopping",
    "www.wikipedia.org": "reference",
    "status.office.com": "business",
    "onedrive.live.com": "cloud",
    "dl.delivery.mp.microsoft.com": "system",
    "windowsupdate.com": "system",
    "crl.microsoft.com": "system",
    "login.microsoftonline.com": "business",
    "graph.microsoft.com": "business",
    "login.salesforce.com": "saas",
    "naXX.salesforce.com": "saas",
    "assets.adobe.com": "creative",
    "www.dropbox.com": "cloud",
    "api.dropboxapi.com": "cloud",
}

DOMAIN_WEIGHTS: dict[str, int] = {
    "login.contoso.com": 26,
    "portal.contoso.com": 18,
    "www.office.com": 16,
    "api.salesforce.com": 12,
    "github.com": 9,
    "cdn.example.net": 7,
    "drive.microsoft.com": 6,
    "update.windows.com": 4,
    "teams.microsoft.com": 13,
    "outlook.office.com": 10,
    "sharepoint.com": 11,
    "app.powerbi.com": 6,
    "docs.microsoft.com": 6,
    "www.google.com": 5,
    "www.bing.com": 4,
    "www.linkedin.com": 3,
    "www.netflix.com": 2,
    "api.github.com": 5,
    "raw.githubusercontent.com": 4,
    "pypi.org": 3,
    "www.npmjs.com": 3,
    "www.amazon.com": 2,
    "www.wikipedia.org": 2,
    "status.office.com": 3,
    "onedrive.live.com": 4,
    "dl.delivery.mp.microsoft.com": 3,
    "windowsupdate.com": 3,
    "crl.microsoft.com": 2,
    "login.microsoftonline.com": 8,
    "graph.microsoft.com": 6,
    "login.salesforce.com": 5,
    "naXX.salesforce.com": 4,
    "assets.adobe.com": 2,
    "www.dropbox.com": 2,
    "api.dropboxapi.com": 2,
}

DOMAIN_FAMILIES: dict[str, tuple[str, ...]] = {
    "m365": ("login.contoso.com", "portal.contoso.com", "www.office.com", "teams.microsoft.com", "outlook.office.com", "sharepoint.com", "status.office.com", "login.microsoftonline.com", "graph.microsoft.com"),
    "browser": ("www.google.com", "www.bing.com", "www.linkedin.com", "www.wikipedia.org", "www.amazon.com", "www.netflix.com", "www.dropbox.com", "www.office.com", "github.com", "drive.microsoft.com", "cdn.example.net"),
    "salesforce": ("api.salesforce.com", "login.salesforce.com", "naXX.salesforce.com", "login.contoso.com", "portal.contoso.com"),
    "github": ("github.com", "api.github.com", "raw.githubusercontent.com", "docs.microsoft.com", "pypi.org", "www.npmjs.com"),
    "update": ("update.windows.com", "windowsupdate.com", "dl.delivery.mp.microsoft.com", "crl.microsoft.com", "cdn.example.net", "status.office.com"),
    "internal": ("login.contoso.com", "portal.contoso.com", "graph.microsoft.com", "sharepoint.com", "onedrive.live.com", "drive.microsoft.com"),
    "cdn": ("cdn.example.net", "onedrive.live.com", "assets.adobe.com", "drive.microsoft.com", "www.dropbox.com"),
    "recursive": ("login.contoso.com", "portal.contoso.com", "api.salesforce.com", "github.com", "login.microsoftonline.com"),
}


class DomainCatalog:
    def __init__(self, random: Random, domains: tuple[str, ...], host_profiles: tuple[dict[str, object], ...] | None = None) -> None:
        self.random = random
        self.domains = domains
        self.host_profiles = host_profiles or ()
        self.domain_categories = DOMAIN_CATEGORIES
        self.domain_weights = DOMAIN_WEIGHTS
        self.domain_families = DOMAIN_FAMILIES

    def weighted_choice(self, options: dict[str, int]) -> str:
        return self.random.choices(
            population=list(options.keys()),
            weights=list(options.values()),
            k=1,
        )[0]

    def choose_domain_for_host(self, host: dict[str, object], app: str | None = None) -> str:
        preferred_raw = host.get("preferred_domains", self.domains)
        preferred = tuple(str(domain) for domain in preferred_raw) if isinstance(preferred_raw, (list, tuple)) else self.domains
        app_key = app if app is not None else ""
        source_domains = tuple(str(domain) for domain in self.domain_families.get(app_key, ())) or preferred

        if source_domains and self.random.random() < 0.85:
            preferred_weights = {domain: self.domain_weights.get(domain, 1) for domain in source_domains}
            return self.weighted_choice(preferred_weights)

        if preferred:
            preferred_weights = {domain: self.domain_weights.get(domain, 1) for domain in preferred}
            return self.weighted_choice(preferred_weights)

        return self.weighted_choice(self.domain_weights)

    def choose_query_type(self, domain: str) -> str:
        if domain.endswith(".contoso.com"):
            return self.random.choices(["A", "AAAA", "CNAME"], weights=[78, 20, 2], k=1)[0]
        if domain == "update.windows.com":
            return self.random.choices(["A", "AAAA"], weights=[85, 15], k=1)[0]
        if domain == "github.com":
            return self.random.choices(["A", "AAAA"], weights=[88, 12], k=1)[0]
        if domain in {"drive.microsoft.com", "www.office.com", "api.salesforce.com"}:
            return self.random.choices(["A", "AAAA", "CNAME"], weights=[80, 18, 2], k=1)[0]
        return self.random.choices(["A", "AAAA", "TXT", "MX"], weights=[75, 20, 3, 2], k=1)[0]

    def build_answer(self, domain: str, query_type: str) -> list[str]:
        if query_type == "AAAA":
            if domain.endswith(".contoso.com"):
                return ["fd00:10:0:1::10"]
            if domain == "update.windows.com":
                return ["2620:1ec:c11::200"]
            return ["2606:4700:4700::1111"]

        if query_type == "MX":
            if domain.endswith(".contoso.com"):
                return ["mail.contoso.com"]
            return ["mail.protection.outlook.com"]

        if query_type == "TXT":
            if domain.endswith(".contoso.com"):
                return ["v=spf1 include:contoso.com -all"]
            return ["v=spf1 include:spf.protection.outlook.com -all"]

        if query_type == "CNAME":
            if domain == "login.contoso.com":
                return ["auth.contoso.com"]
            if domain == "portal.contoso.com":
                return ["portal-frontdoor.contoso.com"]
            return ["cdn.redirect.example.net"]

        if domain.endswith(".contoso.com"):
            return [self.random.choice(("10.20.30.40", "10.20.30.41", "10.20.30.42"))]

        if domain == "update.windows.com":
            return [self.random.choice(("13.107.42.14", "13.107.246.40", "20.190.160.10"))]

        return [self.random.choice(("93.184.216.34", "151.101.1.69", "104.16.123.96"))]
