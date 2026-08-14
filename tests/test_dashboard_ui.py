from hashlib import sha256
from html.parser import HTMLParser
from importlib.resources import files


class DashboardParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.tabs: set[str] = set()
        self.filters: set[str] = set()
        self.assets: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if element_id := values.get("id"):
            self.ids.append(element_id)
        if tab := values.get("data-tab"):
            self.tabs.add(tab)
        if verdict_filter := values.get("data-verdict-filter"):
            self.filters.add(verdict_filter)
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
        "q", "save", "go", "status", "results", "results-empty", "summary", "profile",
        "intake-preview",
        "live-reasoning", "reasoning-run", "reasoning-load", "reasoning-view",
        "live-graph-canvas", "live-graph-detail", "live-graph-tooltip",
        "live-graph-status", "live-graph-fit", "live-graph-pause",
    } <= set(dashboard.ids)
    assert dashboard.filters == {
        "ALL", "FOUND", "UNCERTAIN", "UNVERIFIABLE", "ERROR", "NOT_FOUND",
    }


def test_dashboard_assets_are_local_and_revisioned() -> None:
    dashboard = dashboard_markup()
    web_root = files("recon").joinpath("web")
    style_hash = sha256(web_root.joinpath("style.css").read_bytes()).hexdigest()[:12]
    script_hash = sha256(web_root.joinpath("app.js").read_bytes()).hexdigest()[:12]

    assert dashboard.assets == [
        f"/static/style.css?v={style_hash}",
        f"/static/app.js?v={script_hash}",
    ]
