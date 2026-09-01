from __future__ import annotations

from .contracts import MonitoringContractError, _compact
from .enriched_parsers import ParsedCanonicalEvent
from .entity_context import EventEntityContext, EventEntityReference
from .parsers import QuarantinedRecord, SYSLOG_PARSER_VERSION, parse_syslog_line


def parse_syslog_line_enriched(
    *,
    source_id: str,
    line: str,
    approved_asset_id: str,
) -> ParsedCanonicalEvent | QuarantinedRecord:
    """Add only trusted inventory identity to an already-normalized syslog event.

    The syslog message body is deliberately never parsed for IP, user, process,
    service, or credential-like entities. Correlation identity comes solely from
    the trusted caller-provided inventory asset.
    """

    base = parse_syslog_line(source_id=source_id, line=line)
    if isinstance(base, QuarantinedRecord):
        return base
    try:
        trusted_asset_id = _compact(approved_asset_id, "approved_asset_id", max_len=128)
        context = EventEntityContext(
            event_id=base.event_id,
            references=(
                EventEntityReference.approved_asset(role="asset", asset_id=trusted_asset_id),
            ),
        ).validate()
        return ParsedCanonicalEvent(event=base, entity_context=context).validate()
    except (MonitoringContractError, TypeError, ValueError):
        return QuarantinedRecord(
            source_id=source_id,
            source_type="syslog",
            parser_version=SYSLOG_PARSER_VERSION,
            reason_code="SYSLOG_ENTITY_CONTEXT_INVALID",
            payload_sha256=base.message_sha256,
            observed_at=base.observed_at,
        )
