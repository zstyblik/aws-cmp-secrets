# aws-cmp-secrets

`aws_cmp_secrets` is a script which enables you to compare secrets stored in AWS
Secrets Manager and show difference between the two. It also supports MFA
authentication(interactive), should policy require it.

It utilizes [boto3] under the hood. Also, you need AWS credentials in your
environment(one way or another) and appropriate permissions to access secrets
you want to compare.

**NOTE** that CLI args and output format might change in the future(probably in
10 years from now or so). Ideas to make output format more useable and
user-friendly are welcome, I think.

## Example usage

```Bash
# with interactive MFA authentication and version IDs
aws_cmp_secrets \
    -i \
    -s1 my/secret/foo \
    --version-id1 12345678-1234-1234-1234-123456789012 \
    -s2 my/secret/foo \
    --version-id2 12345678-1234-1234-1234-333333333333
MFA devices:
0: arn:aws:iam::111111111111:mfa/mfa-device1
Choose which MFA device you want to use(0..0): 0
Enter MFA token: 123456
---
a: secret 'my/secret/foo'@'12345678-1234-1234-1234-123456789012'
b: secret 'my/secret/foo'@'12345678-1234-1234-1234-333333333333'
a: 'SOME_KEY':'foo_value'
b: 'SOME_KEY':'bar_value'
a: 'OTHER_KEY':'some_value'
b: '**ABSENT**':'**ABSENT**'

# with secret values masked
aws_cmp_secrets \
    -m \
    -s1 my/secret/foo \
    -s2 my/secret/bar
a: secret 'my/secret/foo'@'AWSCURRENT'
b: secret 'my/secret/bar'@'AWSCURRENT'
a: 'SOME_KEY':'**MASKED**'
b: 'SOME_KEY':'**MASKED**'
```

[boto3]: https://pypi.org/project/boto3/
