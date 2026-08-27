"""Shodan module (keyed): IP_ADDRESS -> open ports / services / hostnames.

Requires a `shodan` key in the vault; the engine skips this module entirely when
the key is absent, so it is invisible in the default keyless configuration."""

from __future__ import annotations

from ..graph_models import Artifact, ArtifactType
from ..keys import VAULT
from ..models import Finding, Verdict
from .base import Module, ModuleContext


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    key = VAULT.get("shodan")
    if not key:  # defensive: engine already gates this
        return
    resp = await ctx.client.fetch(
        f"https://api.shodan.io/shodan/host/{art.normalized}", params={"key": key}
    )
    if resp.status_code == 404:
        await ctx.emit_finding(Finding(
            source="shodan:host", category="network", label=f"Shodan {art.normalized}",
            verdict=Verdict.NOT_FOUND, reasons=["no Shodan data for this IP"]))
        return
    if resp.status_code != 200:
        await ctx.emit_finding(Finding(
            source="shodan:host", category="network", label=f"Shodan {art.normalized}",
            verdict=Verdict.UNVERIFIABLE, reasons=[f"Shodan API status {resp.status_code}"]))
        return

    d = resp.json()
    ports = sorted(d.get("ports", []))
    hostnames = d.get("hostnames", [])
    await ctx.emit_finding(Finding(
        source="shodan:host", category="network", label=f"Shodan {art.normalized}",
        url=None, verdict=Verdict.FOUND, confidence=0.9,
        reasons=[f"{len(ports)} open port(s): {', '.join(map(str, ports[:15]))}"],
        data={"ports": ports, "hostnames": hostnames, "org": d.get("org"),
              "os": d.get("os"), "country": d.get("country_name")},
    ))
    for host in hostnames:
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.HOSTNAME, host, parent=art, source_module="shodan"))


MODULE = Module(
    name="shodan",
    consumes={ArtifactType.IP_ADDRESS},
    produces={ArtifactType.HOSTNAME},
    run=_run,
    reliability_prior=0.85,
    requires_keys=["shodan"],
)
