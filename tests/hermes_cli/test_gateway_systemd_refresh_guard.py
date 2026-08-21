import pytest

import hermes_cli.gateway as gateway


def test_system_service_invocation_is_supervised():
    assert gateway._running_under_systemd({"INVOCATION_ID": "abc123"}) is True


def test_user_service_exec_pid_is_supervised():
    assert gateway._running_under_systemd({"SYSTEMD_EXEC_PID": "42"}) is True


def test_manual_foreground_launch_is_not_supervised():
    assert gateway._running_under_systemd({}) is False


def test_refresh_skips_when_systemd_is_unsupported(monkeypatch):
    monkeypatch.setattr(gateway, "supports_systemd_services", lambda: False)
    refresh_calls = []
    monkeypatch.setattr(
        gateway,
        "refresh_systemd_unit_if_needed",
        lambda **kwargs: refresh_calls.append(kwargs),
    )

    gateway._refresh_systemd_unit_for_gateway_launch()

    assert refresh_calls == []


@pytest.mark.parametrize("marker", ["INVOCATION_ID", "SYSTEMD_EXEC_PID"])
def test_refresh_skips_when_systemd_owns_gateway(monkeypatch, marker):
    monkeypatch.setattr(gateway, "supports_systemd_services", lambda: True)
    monkeypatch.delenv("INVOCATION_ID", raising=False)
    monkeypatch.delenv("SYSTEMD_EXEC_PID", raising=False)
    monkeypatch.setenv(marker, "service-owned")
    refresh_calls = []
    monkeypatch.setattr(
        gateway,
        "refresh_systemd_unit_if_needed",
        lambda **kwargs: refresh_calls.append(kwargs),
    )

    gateway._refresh_systemd_unit_for_gateway_launch()

    assert refresh_calls == []


def test_refreshes_once_for_manual_supported_launch(monkeypatch):
    monkeypatch.setattr(gateway, "supports_systemd_services", lambda: True)
    monkeypatch.setattr(gateway, "_running_under_systemd", lambda: False)
    refresh_calls = []
    monkeypatch.setattr(
        gateway,
        "refresh_systemd_unit_if_needed",
        lambda **kwargs: refresh_calls.append(kwargs),
    )

    gateway._refresh_systemd_unit_for_gateway_launch()

    assert refresh_calls == [{"system": False}]


def test_refresh_error_does_not_block_manual_launch(monkeypatch):
    monkeypatch.setattr(gateway, "supports_systemd_services", lambda: True)
    monkeypatch.setattr(gateway, "_running_under_systemd", lambda: False)

    def fail_refresh(**kwargs):
        raise RuntimeError("refresh failed")

    monkeypatch.setattr(gateway, "refresh_systemd_unit_if_needed", fail_refresh)

    gateway._refresh_systemd_unit_for_gateway_launch()


def test_run_gateway_invokes_refresh_helper_after_preceding_guards(monkeypatch):
    class StopAfterRefresh(Exception):
        pass

    guard_calls = []
    monkeypatch.setattr(gateway, "_guard_official_docker_root_gateway", lambda: guard_calls.append("root"))
    monkeypatch.setattr(gateway, "_guard_named_profile_under_multiplexer", lambda **kwargs: guard_calls.append("profile"))
    monkeypatch.setattr(gateway, "_guard_supervised_gateway_conflict", lambda **kwargs: guard_calls.append("supervised"))
    monkeypatch.setattr(gateway, "_guard_existing_gateway_process_conflict", lambda **kwargs: guard_calls.append("existing"))
    monkeypatch.setattr(gateway, "_windows_console_window_attached", lambda: False)
    monkeypatch.setattr(gateway, "_windows_gateway_breakaway_state", lambda: None)
    monkeypatch.setattr(gateway, "_windows_gateway_should_absorb_console_controls", lambda: False)

    def stop_after_refresh():
        assert guard_calls == ["root", "profile", "supervised", "existing"]
        raise StopAfterRefresh

    monkeypatch.setattr(gateway, "_refresh_systemd_unit_for_gateway_launch", stop_after_refresh)

    with pytest.raises(StopAfterRefresh):
        gateway.run_gateway()
