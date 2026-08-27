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
        self.result_views: set[str] = set()
        self.mention_filters: set[str] = set()
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
        if result_view := values.get("data-result-view"):
            self.result_views.add(result_view)
        if mention_filter := values.get("data-mention-filter"):
            self.mention_filters.add(mention_filter)
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
        "job-cancel",
        "job-retry",
        "research-room",
        "research-phases",
        "research-now-title",
        "research-now-detail",
        "research-milestone",
        "discovery-feed",
        "discovery-observed",
        "discovery-open",
        "results-reading-status",
        "results-overview-empty",
        "result-view-overview",
        "result-view-mentions",
        "result-view-checks",
        "result-view-overview-tab",
        "result-view-mentions-tab",
        "result-view-checks-tab",
        "phone-mentions-explorer",
        "mention-search",
        "evidence-search",
        "results-filter-empty",
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
    assert dashboard.result_views == {"overview", "mentions", "checks"}
    assert dashboard.mention_filters == {"all", "lead", "review", "context"}
    assert dashboard.curtains == 3


def test_dashboard_starts_with_typed_clues_for_one_subject() -> None:
    markup = files("recon").joinpath("web/index.html").read_text(encoding="utf-8")
    script = files("recon").joinpath("web/app.js").read_text(encoding="utf-8")

    assert 'name="subject"' not in markup
    assert "Known identity clues" in markup
    assert "One subject" in markup
    for name in {"name", "username", "email", "phone", "url", "domain", "ip_address"}:
        assert f'name="{name}"' in markup
    assert '<details class="additional-clues">' in markup
    assert "Profile, website and network clues" in markup
    assert ">Start research</button>" in markup
    assert 'name="authorization_basis"' in markup
    assert 'name="authorized"' in markup
    assert "Research is saved automatically" in markup
    assert "function updateClueSummary()" in script
    assert 'reuse.textContent = "Add to identity clues"' in script
    assert 'input.closest(".additional-clues")' in script


def test_dashboard_navigation_prioritizes_common_tasks() -> None:
    markup = files("recon").joinpath("web/index.html").read_text(encoding="utf-8")

    assert "<summary>Start</summary>" in markup
    assert "<summary>Investigate</summary>" in markup
    assert "<summary>Advanced</summary>" in markup
    assert ">New investigation</button>" in markup
    assert ">Saved investigations</button>" in markup


def test_desktop_menus_use_task_oriented_names() -> None:
    source = files("recon").joinpath("desktop.py").read_text(encoding="utf-8")

    assert 'addMenu("&Investigate")' in source
    assert 'addMenu("&Advanced")' in source
    assert 'addMenu("&Application")' in source
    assert '"Software Updates"' in source
    assert 'addMenu("&Navigate")' not in source
    assert '"Update Manager"' not in source


def test_dashboard_progressively_reveals_investigation_workspaces() -> None:
    markup = files("recon").joinpath("web/index.html").read_text(encoding="utf-8")
    script = files("recon").joinpath("web/app.js").read_text(encoding="utf-8")

    assert 'data-scan-stage="start"' in markup
    assert 'data-scan-stage="activity"' in markup
    assert 'data-scan-stage="evidence"' in markup
    assert 'setScanStage("activity")' in script
    assert 'setScanStage("evidence")' in script


def test_results_prioritize_conclusions_and_progressively_reveal_detail() -> None:
    markup = files("recon").joinpath("web/index.html").read_text(encoding="utf-8")
    script = files("recon").joinpath("web/app.js").read_text(encoding="utf-8")
    style = files("recon").joinpath("web/style.css").read_text(encoding="utf-8")

    assert markup.index('id="result-view-overview"') < markup.index('id="result-view-checks"')
    assert markup.index('id="profile"') < markup.index('id="results"')
    assert "What Specter learned" in markup
    assert "Complete source record" in markup
    assert "function setResultView(" in script
    assert "function renderPhoneMentions(" in script
    assert "Possible person-level leads" in script
    assert "Needs human review" in script
    assert "Context only" in script
    assert 'data-open-result-view="mentions"' in script
    assert ".evidence-item-main" in style
    assert ".mention-group-list" in style
    assert ".phone-answer" in style


def test_research_runs_as_a_recoverable_background_job() -> None:
    markup = files("recon").joinpath("web/index.html").read_text(encoding="utf-8")
    script = files("recon").joinpath("web/app.js").read_text(encoding="utf-8")

    assert 'id="job-cancel"' in markup
    assert 'id="job-retry"' in markup
    assert "Research is saved automatically" in markup
    assert 'const ACTIVE_JOB_KEY = "specter.active-job"' in script
    assert "async function restoreActiveResearch()" in script
    assert "/api/jobs?active=true&limit=1" in script
    assert "/cancel`" in script
    assert "/retry`" in script
    assert "new EventSource" not in script


def test_saved_research_and_source_limits_are_actionable() -> None:
    markup = files("recon").joinpath("web/index.html").read_text(encoding="utf-8")
    script = files("recon").joinpath("web/app.js").read_text(encoding="utf-8")

    assert "Saved subjects" in markup
    assert "Sources and limits" in markup
    assert "function preloadTarget(" in script
    assert "Research again" in script
    assert "Change monitoring" in script
    assert "authorization basis for recurring research" in script
    assert "/report/html" in script and "/report/csv" in script
    assert "Applicable policies" in script
    assert "Can establish" in script


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
    icon = files("recon").joinpath("assets/specter.png")
    icon_hash = sha256(icon.read_bytes()).hexdigest()[:12]

    assert "Specter" in markup
    assert markup.count(f'src="/icon.png?v={icon_hash}"') == 2
    assert f'href="/icon.png?v={icon_hash}"' in markup
    assert ">SP<" not in markup
    assert "osint-recon" not in markup


def test_dashboard_emits_native_investigation_notifications() -> None:
    script = files("recon").joinpath("web/app.js").read_text(encoding="utf-8")

    assert 'CustomEvent("specter:notification"' in script
    assert 'desktopNotify(' in script and '"Investigation complete"' in script
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
