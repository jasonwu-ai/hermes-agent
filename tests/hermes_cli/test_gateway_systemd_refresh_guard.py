from hermes_cli.gateway import _running_under_systemd


def test_system_service_invocation_is_supervised():
    assert _running_under_systemd({"INVOCATION_ID": "abc123"}) is True


def test_user_service_exec_pid_is_supervised():
    assert _running_under_systemd({"SYSTEMD_EXEC_PID": "42"}) is True


def test_manual_foreground_launch_is_not_supervised():
    assert _running_under_systemd({}) is False
