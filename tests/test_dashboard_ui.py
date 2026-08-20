from hashlib import sha256
from html.parser import HTMLParser
from importlib.resources import files


class DashboardParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.tabs: set[str] = set()
        self.filters: set[str] = set()
        self.scan_views: set[str] = set()
        self.research_modes: set[str] = set()
        self.research_phases: set[str] = set()
        self.assets: list[str] = []
        self.curtains = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if element_id := values.get("id"):
            self.ids.append(element_id)
        if tab := values.get("data-tab"):
            self.tabs.add(tab)
        if verdict_filter := values.get("data-verdict-filter"):
            self.filters.add(verdict_filter)
        if scan_view := values.get("data-scan-view"):
            self.scan_views.add(scan_view)
        if research_mode := values.get("data-research-mode"):
            self.research_modes.add(research_mode)
        if research_phase := values.get("data-research-phase"):
            self.research_phases.add(research_phase)
        if tag == "details" and "nav-curtain" in (values.get("class") or "").split():
            self.curtains += 1
        if tag == "link" and values.get("rel") == "stylesheet" and values.get("href"):
            self.assets.append(values["href"])
        if tag == "script" and values.get("src"):
            self.assets.append(values["src"])


def dashboard_markup() -> DashboardParser:
    parser = DashboardParser()
    parser.feed(files("recon").joinpath("web/index.html").read_text(encoding="utf-8"))
    return parser


def test_dashboard_has_unique_ids_and_matching_panels() -> None:
    dashboard = dashboard_markup()

    assert len(dashboard.ids) == len(set(dashboard.ids))
    assert dashboard.tabs == {
        "search",
        "investigations",
        "review",
        "timeline",
        "graph",
        "map",
        "insights",
        "reasoning",
        "confidence",
        "sources",
        "keys",
        "governance",
        "administration",
    }
    assert {f"panel-{tab}" for tab in dashboard.tabs} <= set(dashboard.ids)


def test_dashboard_exposes_scan_feedback_and_filters() -> None:
    dashboard = dashboard_markup()

    assert {
        "q",
        "save",
        "go",
        "status",
        "results",
        "results-empty",
        "summary",
        "profile",
        "intake-preview",
        "live-reasoning",
        "reasoning-run",
        "reasoning-load",
        "reasoning-view",
        "live-graph-canvas",
        "live-graph-detail",
        "live-graph-tooltip",
        "live-graph-status",
        "live-graph-fit",
        "live-graph-pause",
        "research-room",
        "research-phases",
        "research-now-title",
        "research-now-detail",
        "research-milestone",
        "discovery-feed",
        "discovery-confirmed",
        "discovery-open",
    } <= set(dashboard.ids)
    assert dashboard.filters == {
        "ALL",
        "FOUND",
        "UNCERTAIN",
        "UNVERIFIABLE",
        "ERROR",
        "NOT_FOUND",
    }
    assert dashboard.scan_views == {"start", "activity", "evidence"}
    assert dashboard.research_modes == {"focus", "explore"}
    assert dashboard.research_phases == {
        "understand",
        "discover",
        "connect",
        "verify",
        "synthesize",
    }
    assert dashboard.curtains == 3


def test_dashboard_progressively_reveals_investigation_workspaces() -> None:
    markup = files("recon").joinpath("web/index.html").read_text(encoding="utf-8")
    script = files("recon").joinpath("web/app.js").read_text(encoding="utf-8")

    assert 'data-scan-stage="start"' in markup
    assert 'data-scan-stage="activity"' in markup
    assert 'data-scan-stage="evidence"' in markup
    assert 'setScanStage("activity")' in script
    assert 'setScanStage("evidence")' in script


def test_dashboard_assets_are_local_and_revisioned() -> None:
    dashboard = dashboard_markup()
    web_root = files("recon").joinpath("web")
    style_bytes = web_root.joinpath("style.css").read_bytes().replace(b"\r\n", b"\n")
    script_bytes = web_root.joinpath("app.js").read_bytes().replace(b"\r\n", b"\n")
    style_hash = sha256(style_bytes).hexdigest()[:12]
    script_hash = sha256(script_bytes).hexdigest()[:12]

    assert dashboard.assets == [
        f"/static/style.css?v={style_hash}",
        f"/static/app.js?v={script_hash}",
    ]


def test_dashboard_uses_specter_branding() -> None:
    markup = files("recon").joinpath("web/index.html").read_text(encoding="utf-8")

    assert "Specter" in markup
    assert ">SP<" in markup
    assert "osint-recon" not in markup


def test_dashboard_emits_native_investigation_notifications() -> None:
    script = files("recon").joinpath("web/app.js").read_text(encoding="utf-8")

    assert 'CustomEvent("specter:notification"' in script
    assert 'desktopNotify("Investigation complete"' in script
    assert 'desktopNotify("Investigation failed"' in script


def test_research_room_is_driven_by_real_activity_events() -> None:
    script = files("recon").joinpath("web/app.js").read_text(encoding="utf-8")

    assert "function updateResearchStory(activity)" in script
    assert "updateResearchStory(node)" in script
    assert "function addDiscoveryEntry(activity, copy)" in script
    assert "function updateFollowedBranch()" in script
    assert "function liveConnectionPath(node)" in script
    assert 'setResearchMode("explore")' in script


def test_research_room_honors_reduced_motion() -> None:
    style = files("recon").joinpath("web/style.css").read_text(encoding="utf-8")
    script = files("recon").joinpath("web/app.js").read_text(encoding="utf-8")

    assert "@media (prefers-reduced-motion: reduce)" in style
    assert 'matchMedia("(prefers-reduced-motion: reduce)")' in script
    assert "reducedGraphMotion.matches" in script
