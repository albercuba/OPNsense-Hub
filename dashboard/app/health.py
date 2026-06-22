from dataclasses import dataclass


@dataclass(frozen=True)
class HealthThresholds:
    warning_misses: int
    critical_misses: int
    warning_recovery_successes: int
    critical_recovery_successes: int


@dataclass(frozen=True)
class HealthState:
    status: str
    missed_checks: int
    success_checks: int


def next_health_state(
    state: HealthState, healthy: bool, thresholds: HealthThresholds
) -> HealthState:
    if healthy:
        success_checks = state.success_checks + 1
        required_successes = thresholds.warning_recovery_successes
        if state.status == "offline":
            required_successes = thresholds.critical_recovery_successes
        status = "online" if success_checks >= required_successes else state.status
        return HealthState(
            status=status,
            missed_checks=0,
            success_checks=success_checks,
        )

    missed_checks = state.missed_checks + 1
    status = state.status
    if missed_checks >= thresholds.critical_misses:
        status = "offline"
    elif missed_checks >= thresholds.warning_misses:
        status = "warning"
    return HealthState(
        status=status,
        missed_checks=missed_checks,
        success_checks=0,
    )
