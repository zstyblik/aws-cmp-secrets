#!/usr/bin/env python3
"""Unit tests for cmp_secrets.py.

MIT License

Copyright (c) 2025 Zdenek Styblik

See LICENSE for details.
"""
import base64
import logging
import sys
from unittest.mock import call
from unittest.mock import Mock  # noqa: I100
from unittest.mock import patch

import pytest

from aws_cmp_secrets import cmp_secrets


@pytest.mark.parametrize(
    "data1,data2,mask_secrets,expected_rc,expected",
    [
        (
            "foo",
            12345,
            False,
            2,
            (
                "a: is of type '<class 'str'>'\n"
                "b: is of type '<class 'int'>'\n"
                "ERROR: cannot compare secrets of different types.\n"
            ),
        ),
        (
            "foo",
            "foo",
            False,
            0,
            "No differences were found.\n",
        ),
        (
            "foo",
            "bar",
            False,
            1,
            "a: 'foo'\nb: 'bar'\n",
        ),
        (
            1234,
            5678,
            False,
            1,
            "a: '1234'\nb: '5678'\n",
        ),
        (
            "foo",
            "bar",
            True,
            1,
            "a: '**MASKED**'\nb: '**MASKED**'\n",
        ),
        (
            {},
            {},
            False,
            0,
            "No differences were found.\n",
        ),
        (
            {"foo": "bar"},
            {"foo": "bar"},
            False,
            0,
            "No differences were found.\n",
        ),
        (
            {"foo": "bar"},
            {},
            False,
            1,
            "a: 'foo':'bar'\nb: '**ABSENT**':'**ABSENT**'\n",
        ),
        (
            {},
            {"foo": "bar"},
            False,
            1,
            "a: '**ABSENT**':'**ABSENT**'\nb: 'foo':'bar'\n",
        ),
        (
            {"foo": "bar"},
            {},
            True,
            1,
            "a: 'foo':'**MASKED**'\nb: '**ABSENT**':'**ABSENT**'\n",
        ),
        (
            {},
            {"foo": "bar"},
            True,
            1,
            "a: '**ABSENT**':'**ABSENT**'\nb: 'foo':'**MASKED**'\n",
        ),
        (
            {"foo": "bar", "lar": "mar"},
            {"lar": "mar"},
            True,
            1,
            "a: 'foo':'**MASKED**'\nb: '**ABSENT**':'**ABSENT**'\n",
        ),
        (
            {"lar": "mar"},
            {"foo": "bar"},
            False,
            1,
            (
                "a: '**ABSENT**':'**ABSENT**'\n"
                "b: 'foo':'bar'\n"
                "a: 'lar':'mar'\n"
                "b: '**ABSENT**':'**ABSENT**'\n"
            ),
        ),
        (
            {"lar": "mar"},
            {"foo": "bar"},
            True,
            1,
            (
                "a: '**ABSENT**':'**ABSENT**'\n"
                "b: 'foo':'**MASKED**'\n"
                "a: 'lar':'**MASKED**'\n"
                "b: '**ABSENT**':'**ABSENT**'\n"
            ),
        ),
    ],
)
def test_cmp_secrets(data1, data2, mask_secrets, expected_rc, expected, capsys):
    """Test that cmp_secrets() works as expected."""
    retval = cmp_secrets.cmp_secrets(data1, data2, mask_secrets)

    assert retval == expected_rc
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == expected


@pytest.mark.parametrize(
    "data,expected",
    [
        (
            {"SecretString": '{"foo":"bar"}'},
            {"foo": "bar"},
        ),
        (
            {"SecretString": '{"fo'},
            '{"fo',
        ),
        (
            {"SecretString": '{"fo'},
            '{"fo',
        ),
        (
            {"SecretBinary": base64.b64encode(b"foo")},
            b"foo",
        ),
        (
            {"SecretBinary": base64.b64encode(b'{"foo":"bar"}')},
            {"foo": "bar"},
        ),
    ],
)
def test_get_secret(data, expected):
    """Test that get_secret() works as expected."""
    secret_name = "py/test/secret"
    ver_id = ""
    mock_cli = Mock()
    mock_cli.get_secret_value.return_value = data
    result = cmp_secrets.get_secret(mock_cli, secret_name, ver_id)

    mock_cli.get_secret_value.assert_called_once_with(SecretId=secret_name)
    assert result == expected


def test_get_secret_version_id():
    """Test that VersionId arg is passed in get_secret() as expected."""
    secret_name = "py/test/secret"
    ver_id = "abcefg"
    data = {"SecretString": '{"foo":"bar"}'}
    expected = {"foo": "bar"}

    mock_cli = Mock()
    mock_cli.get_secret_value.return_value = data
    result = cmp_secrets.get_secret(mock_cli, secret_name, ver_id)

    mock_cli.get_secret_value.assert_called_once_with(
        SecretId=secret_name,
        VersionId="abcefg",
    )
    assert result == expected


def test_get_mfa_devices():
    """Test that get_mfa_devices() works as expected."""
    user_name = "pytest"
    expected = [
        {"SerialNumber": "abc123"},
        {"SerialNumber": "def456"},
        {"SerialNumber": "ghi789"},
    ]
    mock_paginator = Mock()
    mock_paginator.paginate.return_value = iter(
        [
            {
                "MFADevices": [
                    {"SerialNumber": "abc123"},
                ]
            },
            {
                "MFADevices": [
                    {"SerialNumber": "def456"},
                    {"SerialNumber": "ghi789"},
                ]
            },
        ]
    )
    mock_cli = Mock()
    mock_cli.get_paginator.return_value = mock_paginator

    result = cmp_secrets.get_mfa_devices(mock_cli, user_name)

    mock_cli.get_paginator.assert_called_once_with("list_mfa_devices")
    mock_paginator.paginate.assert_called_once_with(UserName=user_name)
    result = sorted(result, key=lambda x: x["SerialNumber"])
    expected = sorted(expected, key=lambda x: x["SerialNumber"])
    assert result == expected


def test_choose_mfa_device(monkeypatch, capsys):
    """Test exceptions and return value of choose_mfa_device()."""
    expected_output = (
        "Entered MFA value 'abc' is invalid\n"
        "Entered MFA value '10' is out of bounds\n"
    )
    responses = iter(["abc", "10", "3"])
    monkeypatch.setattr("builtins.input", lambda msg: next(responses))

    result = cmp_secrets.choose_mfa_device(5, 4)

    assert result == 3
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == expected_output


@pytest.mark.parametrize(
    "max_attempts",
    [
        (0),
        (-1),
        (-99),
    ],
)
def test_choose_mfa_device_max_attempts_low(max_attempts):
    """Test that ValueError is raised when max_attempts is less than 1."""
    with pytest.raises(ValueError) as excinfo:
        cmp_secrets.choose_mfa_device(20, max_attempts)

    assert "max_attempts cannot be less than 1" in str(excinfo.value)


def test_choose_mfa_device_max_attempts_exc(monkeypatch):
    """Test that ValueError is raised when max attempts is reached."""
    responses = iter(["abc", "10"])
    monkeypatch.setattr("builtins.input", lambda msg: next(responses))
    with pytest.raises(ValueError) as excinfo:
        cmp_secrets.choose_mfa_device(2, 1)

    assert "Max attempts reached - giving up" in str(excinfo.value)


@pytest.mark.parametrize(
    "mfa_count",
    [
        (0),
        (-1),
        (-99),
    ],
)
def test_choose_mfa_device_mfa_count_low(mfa_count):
    """Test that ValueError is raised when mfa_count is less than 1."""
    with pytest.raises(ValueError) as excinfo:
        cmp_secrets.choose_mfa_device(mfa_count, 1)

    assert "mfa_count cannot be less than 1" in str(excinfo.value)


@patch("aws_cmp_secrets.cmp_secrets.get_mfa_devices")
@patch("aws_cmp_secrets.cmp_secrets.choose_mfa_device")
def test_mfa_auth(mock_choose_mfa, mock_mfa_devices, capsys, monkeypatch):
    """Test that mfa_auth() works as expected."""
    logger = logging.getLogger("pytest-logger")

    mock_region = "py-region"
    mock_mfa_token = "123456789"
    mock_aws_username = "pyuser"
    mock_client = Mock()
    mock_client.get_user.return_value = {
        "User": {"UserName": mock_aws_username}
    }
    mock_client.get_session_token.return_value = {
        "Credentials": {
            "AccessKeyId": "pykid",
            "SecretAccessKey": "pyakey",
            "SessionToken": "pytoken",
        }
    }
    mock_session = Mock()
    mock_session.client.return_value = mock_client
    mock_mfa_devices.return_value = [
        {"SerialNumber": "mfa-1234"},
        {"SerialNumber": "mfa-5678"},
    ]
    mock_choose_mfa.return_value = 0

    monkeypatch.setattr("builtins.input", lambda _: mock_mfa_token)
    result = cmp_secrets.mfa_auth(logger, mock_session, mock_region)

    mock_client.get_user.assert_called_once_with()
    mock_client.get_session_token.assert_called_once_with(
        DurationSeconds=900,
        SerialNumber="mfa-1234",
        TokenCode=mock_mfa_token,
    )
    mock_choose_mfa.assert_called_once_with(2, cmp_secrets.MAX_ATTEMPTS)
    mock_mfa_devices.assert_called_once_with(mock_client, mock_aws_username)

    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == "MFA devices:\n0: mfa-1234\n1: mfa-5678\n---\n"
    assert result != mock_session


@patch("aws_cmp_secrets.cmp_secrets.get_mfa_devices")
def test_mfa_auth_no_devices(mock_mfa_devices, capsys):
    """Test that mfa_auth() works as expected when there are no MFA devices."""
    logger = logging.getLogger("pytest-logger")

    mock_region = "py-region"
    mock_mfa_devices.return_value = []

    mock_client = Mock()
    mock_client.get_user.return_value = {"User": {"UserName": "pyuser"}}
    mock_session = Mock()
    mock_session.client.return_value = mock_client

    result = cmp_secrets.mfa_auth(logger, mock_session, mock_region)

    mock_session.client.assert_called_once_with("iam")
    mock_client.get_user.assert_called_once_with()
    mock_mfa_devices.assert_called_once_with(mock_client, "pyuser")

    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == "There are no MFA devices - skip MFA auth.\n"
    assert result == mock_session


@patch("aws_cmp_secrets.cmp_secrets.boto3.Session")
@patch("aws_cmp_secrets.cmp_secrets.get_secret")
@patch("aws_cmp_secrets.cmp_secrets.mfa_auth")
def test_main_no_mfa(mock_mfa_auth, mock_get_secret, mock_new_session, capsys):
    """Test that main() works as expected.

    * boto3.Session is called with region from CLI args
    * VersionId
    * no MFA auth
    * retcode
    """
    aws_region = "pyregion"
    secret_name1 = "py/test/one"
    version_id1 = "abc123"
    secret_name2 = "py/test/one"
    version_id2 = "efg123"
    expected_out = (
        "a: secret 'py/test/one'@'abc123'\n"
        "b: secret 'py/test/one'@'efg123'\n"
        "a: 'foo'\n"
        "b: 'bar'\n"
    )

    mock_sm_manager = Mock()
    mock_session = Mock()
    mock_session.client.return_value = mock_sm_manager
    mock_new_session.return_value = mock_session

    mock_get_secret.side_effect = ["foo", "bar"]

    exception = None
    args = [
        "aws_cmp_secrets.py",
        "--region",
        aws_region,
        "-s1",
        secret_name1,
        "--version-id1",
        version_id1,
        "-s2",
        secret_name2,
        "--version-id2",
        version_id2,
    ]
    with patch.object(sys, "argv", args):
        try:
            cmp_secrets.main()
        except SystemExit as sys_exit:
            exception = sys_exit

    assert isinstance(exception, SystemExit) is True
    assert exception.code == 1
    mock_new_session.assert_called_once_with(region_name=aws_region)
    mock_session.client.assert_called_once_with("secretsmanager")
    mock_mfa_auth.assert_not_called()
    expected_calls = [
        call(mock_sm_manager, secret_name1, version_id1),
        call(mock_sm_manager, secret_name2, version_id2),
    ]
    assert mock_get_secret.mock_calls == expected_calls
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == expected_out


@patch("aws_cmp_secrets.cmp_secrets.boto3.Session")
@patch("aws_cmp_secrets.cmp_secrets.get_secret")
@patch("aws_cmp_secrets.cmp_secrets.mfa_auth")
def test_main_masked(mock_mfa_auth, mock_get_secret, mock_new_session, capsys):
    """Test that main() works as expected.

    * masked
    * boto3.Session is called with region from CLI args
    * VersionId
    * no MFA auth
    * retcode
    """
    aws_region = "pyregion"
    secret_name1 = "py/test/one"
    version_id1 = "abc123"
    secret_name2 = "py/test/one"
    version_id2 = "efg123"
    expected_out = (
        "a: secret 'py/test/one'@'abc123'\n"
        "b: secret 'py/test/one'@'efg123'\n"
        "a: '**MASKED**'\n"
        "b: '**MASKED**'\n"
    )

    mock_sm_manager = Mock()
    mock_session = Mock()
    mock_session.client.return_value = mock_sm_manager
    mock_new_session.return_value = mock_session

    mock_get_secret.side_effect = ["foo", "bar"]

    exception = None
    args = [
        "aws_cmp_secrets.py",
        "--region",
        aws_region,
        "-m",
        "-s1",
        secret_name1,
        "--version-id1",
        version_id1,
        "-s2",
        secret_name2,
        "--version-id2",
        version_id2,
    ]
    with patch.object(sys, "argv", args):
        try:
            cmp_secrets.main()
        except SystemExit as sys_exit:
            exception = sys_exit

    assert isinstance(exception, SystemExit) is True
    assert exception.code == 1
    mock_new_session.assert_called_once_with(region_name=aws_region)
    mock_session.client.assert_called_once_with("secretsmanager")
    mock_mfa_auth.assert_not_called()
    expected_calls = [
        call(mock_sm_manager, secret_name1, version_id1),
        call(mock_sm_manager, secret_name2, version_id2),
    ]
    assert mock_get_secret.mock_calls == expected_calls
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == expected_out


@patch("aws_cmp_secrets.cmp_secrets.boto3.Session")
@patch("aws_cmp_secrets.cmp_secrets.get_secret")
@patch("aws_cmp_secrets.cmp_secrets.mfa_auth")
def test_main_with_mfa(
    mock_mfa_auth, mock_get_secret, mock_new_session, capsys
):
    """Test that main() works as expected.

    * boto3.Session is called with default region from CLI args
    * no VersionId
    * with MFA auth
    * retcode
    """
    aws_region = None
    secret_name1 = "py/test/one"
    version_id1 = ""
    secret_name2 = "py/test/two"
    version_id2 = ""
    expected_out = (
        "a: secret 'py/test/one'@'AWSCURRENT'\n"
        "b: secret 'py/test/two'@'AWSCURRENT'\n"
        "No differences were found.\n"
    )

    mock_sm_manager = Mock()
    mock_new_session.return_value = Mock()
    mock_temp_session = Mock()
    mock_temp_session.client.return_value = mock_sm_manager
    mock_mfa_auth.return_value = mock_temp_session

    mock_get_secret.side_effect = ["foo", "foo"]

    exception = None
    args = [
        "aws_cmp_secrets.py",
        "-i",
        "-s1",
        secret_name1,
        "-s2",
        secret_name2,
    ]
    with patch.object(sys, "argv", args):
        try:
            cmp_secrets.main()
        except SystemExit as sys_exit:
            exception = sys_exit

    assert isinstance(exception, SystemExit) is True
    assert exception.code == 0
    mock_new_session.assert_called_once_with(region_name=aws_region)
    mock_temp_session.client.assert_called_once_with("secretsmanager")
    mock_mfa_auth.assert_called()
    expected_calls = [
        call(mock_sm_manager, secret_name1, version_id1),
        call(mock_sm_manager, secret_name2, version_id2),
    ]
    assert mock_get_secret.mock_calls == expected_calls
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == expected_out


@pytest.mark.parametrize(
    "data,key,prefix,mask_secrets,expected",
    [
        # Key is absent; mask False
        (
            {},
            "pykey",
            "p",
            False,
            "p: '**ABSENT**':'**ABSENT**'\n",
        ),
        # Key is absent; mask True
        (
            {"foo": "bar"},
            "pykey",
            "p",
            True,
            "p: '**ABSENT**':'**ABSENT**'\n",
        ),
        # Key is present; mask False
        (
            {"pykey": "testval", "foo": "bar"},
            "pykey",
            "p",
            False,
            "p: 'pykey':'testval'\n",
        ),
        # Key is present; mask True
        (
            {"pykey": "testval", "lar": "mar"},
            "pykey",
            "p",
            True,
            "p: 'pykey':'**MASKED**'\n",
        ),
    ],
)
def test_printout_dict_diff(data, key, prefix, mask_secrets, expected, capsys):
    """Test that printout_dict_diff() works as expected."""
    retval = cmp_secrets.printout_dict_diff(data, key, prefix, mask_secrets)

    assert retval is None
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == expected


@pytest.mark.parametrize(
    "secret_name,ver_id,prefix,expected",
    [
        (
            "pytest1",
            "",
            "p",
            "p: secret 'pytest1'@'AWSCURRENT'\n",
        ),
        (
            "pytest2",
            "abc",
            "q",
            "q: secret 'pytest2'@'abc'\n",
        ),
    ],
)
def test_printout_header(secret_name, ver_id, prefix, expected, capsys):
    """Test that printout_header() works as expected."""
    retval = cmp_secrets.printout_header(secret_name, ver_id, prefix)

    assert retval is None
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == expected
