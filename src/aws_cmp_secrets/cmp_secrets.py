#!/usr/bin/env python3
"""Utility for comparison of secrets in AWS Secrets Manager.

MIT License

Copyright (c) 2025 Zdenek Styblik

See LICENSE for details.
"""
import argparse
import base64
import json
import logging
import sys
from typing import Any
from typing import Dict
from typing import List

import boto3

MAX_ATTEMPTS = 4


def calc_log_level(count: int) -> int:
    """Return logging log level as int based on count."""
    log_level = 40 - max(count, 0) * 10
    log_level = max(log_level, 10)
    return log_level


def cmp_secrets(data1: Any, data2: Any, mask_secrets: bool) -> int:
    """Compare secrets and printout differences, if there are any."""
    if not isinstance(data1, type(data2)):
        print("a: is of type '{}'".format(type(data1)))
        print("b: is of type '{}'".format(type(data2)))
        print("ERROR: cannot compare secrets of different types.")
        return 2

    if not isinstance(data1, dict):
        # secret1 and secret2 are of the same type, but not dict.
        if data1 == data2:
            print("No differences were found.")
            return 0

        print("a: '{}'".format(data1 if not mask_secrets else "**MASKED**"))
        print("b: '{}'".format(data2 if not mask_secrets else "**MASKED**"))
        return 1

    data_set1 = {(key, value) for key, value in data1.items()}
    data_set2 = {(key, value) for key, value in data2.items()}
    diff = data_set1.symmetric_difference(data_set2)
    if not diff:
        print("No differences were found.")
        return 0

    scratch = {item[0] for item in diff}
    for key in sorted(scratch):
        printout_dict_diff(data1, key, "a", mask_secrets)
        printout_dict_diff(data2, key, "b", mask_secrets)

    return 1


def get_secret(
    secrets_cli, secret_name: str, version_id: str = ""
) -> Dict[Any, Any] | str:
    """Return decrypted data stored in AWS Secrets Manager."""
    kwargs = {"SecretId": secret_name}
    if version_id:
        kwargs["VersionId"] = version_id

    rsp = secrets_cli.get_secret_value(**kwargs)
    # Decrypts secret using the associated KMS CMK.
    if "SecretString" in rsp:
        data = rsp["SecretString"]
    else:
        # Decode binary secret
        data = base64.b64decode(rsp["SecretBinary"])

    try:
        secret_data = json.loads(data)
    except json.decoder.JSONDecodeError:
        secret_data = data

    return secret_data


def get_mfa_devices(iam_cli, user_name: str) -> List:
    """Get MFA devices for IAM user identified by user name."""
    paginator = iam_cli.get_paginator("list_mfa_devices")
    response_iterator = paginator.paginate(UserName=user_name)
    mfa_devices = []
    for page in response_iterator:
        devices = page.get("MFADevices", [])
        for device in devices:
            mfa_devices.append(device)

    return mfa_devices


def choose_mfa_device(mfa_count: int, max_attempts: int) -> int:
    """Ask user which MFA device to use and return its index."""
    if mfa_count < 1:
        raise ValueError("mfa_count cannot be less than 1")

    if max_attempts < 1:
        raise ValueError("max_attempts cannot be less than 1")

    mfa_idx = -1
    attempt = 0
    while True:
        attempt = attempt + 1
        mfa_idx = -1
        if attempt > max_attempts:
            raise ValueError("Max attempts reached - giving up")

        user_input = input(
            "Choose which MFA device you want to use(0..{:d}): ".format(
                mfa_count - 1
            )
        )
        try:
            mfa_idx = int(user_input)
        except ValueError:
            print("Entered MFA value '{}' is invalid".format(user_input))
            continue

        if mfa_idx < 0 or mfa_idx > mfa_count - 1:
            print("Entered MFA value '{}' is out of bounds".format(mfa_idx))
            continue

        break

    return mfa_idx


def mfa_auth(logger, aws_session, aws_region_name: str):
    """Perform MFA auth and return new Session with temporary credentials."""
    iam_cli = aws_session.client("iam")
    rsp_user = iam_cli.get_user()
    logger.debug("User rsp: %s", rsp_user)
    user_name = rsp_user["User"]["UserName"]

    mfa_devices = get_mfa_devices(iam_cli, user_name)
    if not mfa_devices:
        print("There are no MFA devices - skip MFA auth.")
        return aws_session

    mfa_devices = dict(enumerate(mfa_devices))
    print("MFA devices:")
    for idx, mfa_device in mfa_devices.items():
        print("{:d}: {}".format(idx, mfa_device["SerialNumber"]))

    mfa_idx = choose_mfa_device(len(mfa_devices), MAX_ATTEMPTS)
    mfa_sn = mfa_devices[mfa_idx]["SerialNumber"]
    mfa_token = input("Enter MFA token: ")
    sts_cli = aws_session.client("sts")
    rsp = sts_cli.get_session_token(
        DurationSeconds=900,  # min is 900sec
        SerialNumber=mfa_sn,  # MFA S/N
        TokenCode=mfa_token,  # MFA token
    )

    aws_tmp_session = boto3.Session(
        aws_access_key_id=rsp["Credentials"]["AccessKeyId"],
        aws_secret_access_key=rsp["Credentials"]["SecretAccessKey"],
        aws_session_token=rsp["Credentials"]["SessionToken"],
        region_name=aws_region_name,
    )
    print("---")
    return aws_tmp_session


def main():
    """Get secrets from AWS, compare them and printout results."""
    args = parse_args()
    logging.basicConfig(level=args.log_level, stream=sys.stdout)
    logger = logging.getLogger("aws_secrets_manager_diff")

    aws_session = boto3.Session(region_name=args.aws_region_name)
    if args.interactive:
        aws_session = mfa_auth(logger, aws_session, args.aws_region_name)

    secrets_cli = aws_session.client("secretsmanager")
    try:
        data1 = get_secret(secrets_cli, args.secret_name1, args.version_id1)
        data2 = get_secret(secrets_cli, args.secret_name2, args.version_id2)
    except secrets_cli.exceptions.ClientError as error:
        print("ERROR: Failed to get one of the secrets due to exception.")
        if error.response["Error"]["Code"] == "AccessDeniedException":
            print(
                "HINT: try to turn on interactive mode and authenticate "
                " with MFA device."
            )
            print("HINT: this might be required by IAM policy.")

        raise

    printout_header(args.secret_name1, args.version_id1, "a")
    printout_header(args.secret_name2, args.version_id2, "b")
    retval = cmp_secrets(data1, data2, args.mask_secrets)
    sys.exit(retval)


def parse_args() -> argparse.Namespace:
    """Return parsed CLI args."""
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Utility for comparison of secrets in AWS Secrets Manager.",
        epilog="AWS cmp secrets by Zdenek Styblik",
    )
    parser.add_argument(
        "--region",
        default=None,
        dest="aws_region_name",
        type=str,
        help="Name of AWS region.",
    )
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        default=False,
        help="Turns on interactive mode and asks for MFA token.",
    )
    parser.add_argument(
        "-m",
        "--mask-secrets",
        action="store_true",
        default=False,
        dest="mask_secrets",
        help="Don't show secret values.",
    )
    parser.add_argument(
        "-s1",
        "--secret1",
        dest="secret_name1",
        required=True,
        type=str,
        help="Name or ARN of 2nd Secrets Manager secret.",
    )
    parser.add_argument(
        "--version-id1",
        default="",
        dest="version_id1",
        type=str,
        help="Version ID of 1st secret.",
    )
    parser.add_argument(
        "-s2",
        "--secret2",
        dest="secret_name2",
        required=True,
        type=str,
        help="Name or ARN of 2nd Secrets Manager secret.",
    )
    parser.add_argument(
        "--version-id2",
        default="",
        dest="version_id2",
        type=str,
        help="Version ID of 2nd secret.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase log level verbosity. Can be passed multiple times.",
    )
    args = parser.parse_args()
    args.log_level = calc_log_level(args.verbose)
    return args


def printout_dict_diff(
    data: Dict[Any, Any],
    key: str,
    prefix: str,
    mask_secrets: bool,
) -> None:
    """Printout of difference for given dict and key."""
    if key in data:
        a_key = key
        if mask_secrets:
            a_value = "**MASKED**"
        else:
            a_value = data.get(key, "**ABSENT**")
    else:
        a_key = "**ABSENT**"
        a_value = "**ABSENT**"

    print("{:s}: '{}':'{}'".format(prefix, a_key, a_value))


def printout_header(secret_name: str, ver_id: str, prefix: str) -> None:
    """Printout header."""
    if not ver_id:
        ver_id = "AWSCURRENT"

    print("{:s}: secret '{:s}'@'{:s}'".format(prefix, secret_name, ver_id))


if __name__ == "__main__":
    main()
