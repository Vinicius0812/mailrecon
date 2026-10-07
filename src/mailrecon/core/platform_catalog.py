"""MailRecon-owned profile pivots and narrowly scoped public API rules."""

from dataclasses import dataclass
import re
from types import MappingProxyType
from urllib.parse import quote, urlsplit


@dataclass(frozen=True, slots=True)
class PlatformSpec:
    name: str
    profile_template: str
    search_template: str
    rule_id: str = "manual_only"
    rule_version: str = "1"
    api_template: str | None = None
    documentation_url: str | None = None

    def profile_url(self, handle: str) -> str:
        return self.profile_template.format(handle=quote(handle, safe=""))

    def search_url(self, handle: str) -> str:
        return self.search_template.format(handle=quote(handle, safe=""))

    def api_url(self, handle: str) -> str:
        if self.api_template is None or not self.accepts_handle(handle):
            raise ValueError("No exact-username API rule for this handle")
        return self.api_template.format(handle=quote(handle, safe=""))

    def accepts_handle(self, handle: str) -> bool:
        pattern = {
            "github_user": r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?",
            "gitlab_user": r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}",
        }.get(self.rule_id, r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}")
        return bool(re.fullmatch(pattern, handle)) and ".." not in handle


PLATFORMS = (
    PlatformSpec("LinkedIn", "https://www.linkedin.com/in/{handle}/", "https://www.google.com/search?q=site%3Alinkedin.com%2Fin+%22{handle}%22"),
    PlatformSpec("Instagram", "https://www.instagram.com/{handle}/", "https://www.google.com/search?q=site%3Ainstagram.com+%22{handle}%22"),
    PlatformSpec("Facebook", "https://www.facebook.com/{handle}", "https://www.google.com/search?q=site%3Afacebook.com+%22{handle}%22"),
    PlatformSpec("GitHub", "https://github.com/{handle}", "https://www.google.com/search?q=site%3Agithub.com+%22{handle}%22", "github_user", "1", "https://api.github.com/users/{handle}", "https://docs.github.com/en/rest/users/users#get-a-user"),
    PlatformSpec("GitLab", "https://gitlab.com/{handle}", "https://www.google.com/search?q=site%3Agitlab.com+%22{handle}%22", "gitlab_user", "1", "https://gitlab.com/api/v4/users?username={handle}", "https://docs.gitlab.com/api/users/"),
    PlatformSpec("X", "https://x.com/{handle}", "https://www.google.com/search?q=site%3Ax.com+%22{handle}%22"),
    PlatformSpec("Spotify", "https://open.spotify.com/search/{handle}", "https://www.google.com/search?q=site%3Aopen.spotify.com+%22{handle}%22"),
    PlatformSpec("Telegram", "https://t.me/{handle}", "https://www.google.com/search?q=site%3At.me+%22{handle}%22"),
    PlatformSpec("Gravatar", "https://gravatar.com/{handle}", "https://www.google.com/search?q=site%3Agravatar.com+%22{handle}%22"),
)


def validate_catalog(specs: tuple[PlatformSpec, ...]) -> None:
    names = set()
    rules = {
        "GitHub": ("github_user", "https://api.github.com/users/{handle}", "https://github.com/{handle}"),
        "GitLab": ("gitlab_user", "https://gitlab.com/api/v4/users?username={handle}", "https://gitlab.com/{handle}"),
    }
    for spec in specs:
        if spec.name in names or not spec.rule_version:
            raise ValueError("Duplicate platform or missing rule version")
        names.add(spec.name)
        for template in (spec.profile_template, spec.search_template):
            parsed = urlsplit(template)
            if (template.count("{handle}") != 1 or parsed.scheme != "https"
                    or not parsed.hostname or parsed.username or parsed.password or parsed.fragment
                    or "{" in parsed.netloc or "}" in parsed.netloc):
                raise ValueError("Invalid catalog URL template")
            template.format(handle="test")
        if spec.rule_id == "manual_only":
            if spec.api_template is not None:
                raise ValueError("Manual pivots cannot have an API endpoint")
        elif rules.get(spec.name) != (spec.rule_id, spec.api_template, spec.profile_template):
            raise ValueError("Unknown or altered public API rule")
        elif not spec.documentation_url:
            raise ValueError("API rules require documentation")


validate_catalog(PLATFORMS)
PLATFORM_BY_NAME = MappingProxyType({spec.name: spec for spec in PLATFORMS})
