from app.health import HealthState, HealthThresholds, next_health_state

THRESHOLDS = HealthThresholds(
    warning_misses=2,
    critical_misses=3,
    warning_recovery_successes=1,
    critical_recovery_successes=2,
)


def test_marks_warning_after_two_missed_checks():
    state = HealthState(status="online", missed_checks=0, success_checks=0)

    state = next_health_state(state, healthy=False, thresholds=THRESHOLDS)
    assert state.status == "online"
    assert state.missed_checks == 1

    state = next_health_state(state, healthy=False, thresholds=THRESHOLDS)
    assert state.status == "warning"
    assert state.missed_checks == 2


def test_marks_offline_after_three_missed_checks():
    state = HealthState(status="warning", missed_checks=2, success_checks=0)

    state = next_health_state(state, healthy=False, thresholds=THRESHOLDS)

    assert state.status == "offline"
    assert state.missed_checks == 3


def test_recovers_warning_after_one_success():
    state = HealthState(status="warning", missed_checks=2, success_checks=0)

    state = next_health_state(state, healthy=True, thresholds=THRESHOLDS)

    assert state.status == "online"
    assert state.missed_checks == 0
    assert state.success_checks == 1


def test_recovers_offline_after_two_successes():
    state = HealthState(status="offline", missed_checks=3, success_checks=0)

    state = next_health_state(state, healthy=True, thresholds=THRESHOLDS)
    assert state.status == "offline"
    assert state.success_checks == 1

    state = next_health_state(state, healthy=True, thresholds=THRESHOLDS)
    assert state.status == "online"
    assert state.missed_checks == 0
    assert state.success_checks == 2
