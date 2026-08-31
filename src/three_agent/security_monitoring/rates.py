from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CounterRateResult:
    status: str
    delta: int | None
    rate_per_second: float | None
    utilization_pct: float | None
    reason_code: str | None = None


def calculate_counter_rate(
    *,
    previous: int | None,
    current: int | None,
    elapsed_seconds: float,
    counter_bits: int = 64,
    scale: float = 1.0,
    interface_speed_bps: int | None = None,
    previous_interface_speed_bps: int | None = None,
    rebooted: bool = False,
) -> CounterRateResult:
    """Calculate a counter delta/rate without manufacturing values across discontinuities."""

    if previous is None or current is None:
        return CounterRateResult("discontinuity", None, None, None, "MISSING_SAMPLE")
    if elapsed_seconds <= 0:
        return CounterRateResult("discontinuity", None, None, None, "INVALID_INTERVAL")
    if rebooted:
        return CounterRateResult("discontinuity", None, None, None, "DEVICE_REBOOT")
    if counter_bits not in {32, 64}:
        raise ValueError("counter_bits must be 32 or 64")
    if previous < 0 or current < 0:
        return CounterRateResult("discontinuity", None, None, None, "NEGATIVE_COUNTER")
    if interface_speed_bps is not None and interface_speed_bps <= 0:
        return CounterRateResult("discontinuity", None, None, None, "INVALID_INTERFACE_SPEED")
    if (
        previous_interface_speed_bps is not None
        and interface_speed_bps is not None
        and previous_interface_speed_bps != interface_speed_bps
    ):
        return CounterRateResult("discontinuity", None, None, None, "INTERFACE_SPEED_CHANGED")

    if current >= previous:
        delta = current - previous
    else:
        modulus = 1 << counter_bits
        # Treat only a plausible near-boundary transition as wrap. A large arbitrary
        # decrease is more safely classified as reset/discontinuity.
        near_top = previous >= int(modulus * 0.90)
        near_bottom = current <= int(modulus * 0.10)
        if near_top and near_bottom:
            delta = modulus - previous + current
        else:
            return CounterRateResult("discontinuity", None, None, None, "COUNTER_RESET")

    rate = (float(delta) * float(scale)) / float(elapsed_seconds)
    utilization = None
    if interface_speed_bps is not None:
        utilization = (rate / float(interface_speed_bps)) * 100.0
    return CounterRateResult("ok", delta, rate, utilization, None)


def calculate_octet_bandwidth(**kwargs) -> CounterRateResult:
    """Convert byte/octet counters to bits per second."""

    return calculate_counter_rate(scale=8.0, **kwargs)
