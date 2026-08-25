"""Deterministic phone parsing and numbering-plan metadata.

This collector never probes accounts or calls a remote lookup service. Carrier,
location, and line-type values describe numbering-plan allocation data; they do
not identify the current subscriber.
"""

from __future__ import annotations

from typing import Awaitable, Callable

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

from ..http_client import RateLimitedClient
from ..models import Finding, Query, Verdict

EmitFn = Callable[[Finding], Awaitable[None]]


_TYPE_NAMES = {
    phonenumbers.PhoneNumberType.FIXED_LINE: "fixed_line",
    phonenumbers.PhoneNumberType.MOBILE: "mobile",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_or_mobile",
    phonenumbers.PhoneNumberType.TOLL_FREE: "toll_free",
    phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium_rate",
    phonenumbers.PhoneNumberType.SHARED_COST: "shared_cost",
    phonenumbers.PhoneNumberType.VOIP: "voip",
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal_number",
    phonenumbers.PhoneNumberType.PAGER: "pager",
    phonenumbers.PhoneNumberType.UAN: "uan",
    phonenumbers.PhoneNumberType.VOICEMAIL: "voicemail",
    phonenumbers.PhoneNumberType.UNKNOWN: "unknown",
}


async def collect(
    query: Query,
    client: RateLimitedClient,
    emit: EmitFn,
    *,
    default_region: str | None = None,
) -> None:
    raw = query.phone
    if not raw:
        return
    try:
        num = phonenumbers.parse(raw, default_region)
    except phonenumbers.NumberParseException as e:
        await emit(Finding(
            source="phone:parse", category="phone", label="Phone parse",
            verdict=Verdict.ERROR,
            reasons=[
                "could not parse the number; include a country code or configure "
                f"RECON_PHONE_DEFAULT_REGION: {e}"
            ],
        ))
        return

    possible = phonenumbers.is_possible_number(num)
    valid = phonenumbers.is_valid_number(num)
    if not possible or not valid:
        reason = (
            "number length is not possible under the numbering plan"
            if not possible
            else "number has a possible length but is not assigned a valid numbering-plan pattern"
        )
        await emit(Finding(
            source="phone:validate", category="phone", label="Phone number",
            verdict=Verdict.NOT_FOUND, confidence=0.0,
            reasons=[reason],
        ))
        return

    region_code = phonenumbers.region_code_for_number(num)
    description = geocoder.description_for_number(num, "en") or None
    country = geocoder.country_name_for_number(num, "en") or None
    carrier_name = carrier.name_for_number(num, "en") or None
    e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
    await emit(Finding(
        source="phone:validate", category="phone", label="Phone metadata",
        verdict=Verdict.FOUND, confidence=0.85,
        reasons=[
            "Valid number parsed locally with libphonenumber; no lookup request was made.",
            "Carrier, area, and line-type values are allocation metadata, not subscriber "
            "identity, and may be stale after number portability.",
        ],
        signals={"phone_e164": e164},
        data={
            "e164": e164,
            "international": phonenumbers.format_number(
                num, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            ),
            "national": phonenumbers.format_number(
                num, phonenumbers.PhoneNumberFormat.NATIONAL
            ),
            "rfc3966": phonenumbers.format_number(
                num, phonenumbers.PhoneNumberFormat.RFC3966
            ),
            "region": description,
            "region_code": region_code,
            "country": country,
            "country_code": num.country_code,
            "national_number": str(num.national_number),
            "carrier": carrier_name,
            "line_type": _TYPE_NAMES.get(phonenumbers.number_type(num), "unknown"),
            "timezones": list(timezone.time_zones_for_number(num)),
            "possible": possible,
            "valid_for_region": (
                phonenumbers.is_valid_number_for_region(num, region_code)
                if region_code
                else None
            ),
            "international_dialling_available": (
                phonenumbers.can_be_internationally_dialled(num)
            ),
            "number_portability_supported": (
                phonenumbers.is_mobile_number_portable_region(region_code)
                if region_code
                else None
            ),
            "geographic_area_code_length": (
                phonenumbers.length_of_geographical_area_code(num)
            ),
            "national_destination_code_length": (
                phonenumbers.length_of_national_destination_code(num)
            ),
        },
    ))
