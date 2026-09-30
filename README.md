# aws-sso

`aws_sso.py` is a small Python CLI that logs in to AWS IAM Identity Center (AWS SSO), fetches role credentials, and writes them into your local AWS config files so you can use the AWS CLI and SDKs without manually copying tokens.

## What it does

- Opens the browser-based AWS SSO device flow (Requires you to be signed on AWS SSO/Identity Center).
- Lets you pick an AWS account and role.
- Writes short-lived credentials to `~/.aws/credentials`.
- Writes the selected region to `~/.aws/config`.
- Reuses a cached SSO token when possible.
- Skips the login flow if the current credentials are still valid.

## Requirements

- macOS, Linux, or Windows with Python 3.10 or newer.
- An AWS IAM Identity Center setup with access to the SSO start URL.
- Permission to write to your home directory under `~/.aws`.

## Install

Create a virtual environment and install the dependencies used by the script:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install boto3 botocore typer rich
```

If you prefer, you can install those packages into any existing Python environment instead.

## Configure

The script looks for an optional file named `.aws_sso_details` in the same folder where you run it. We added this to speed up and reuse SSO settings, so you can add your SSO start URL and default region there:

```ini
start_url=https://your-company.awsapps.com/start
region=us-east-1
```

Otherwise, you can also pass those values on the command line with `--start-url` and `--region`.

## Run

From the `aws-sso` folder, run:

```bash
python aws_sso.py
```

Optional flags:

- `--start-url` or `-u`: override the AWS SSO start URL.
- `--region` or `-r`: override the AWS region.
- `--profile` or `-p`: name of the AWS profile to write in `~/.aws/credentials`.
- `--refresh`: force a new SSO login even if valid credentials already exist.
- `--switch` or `-s`: List accounts again and switch account/role.

## Typical workflow

1. Run `python aws_sso.py`.
2. Sign in in the browser window that opens.
3. Pick the AWS account and role you want to use.
4. Use the generated credentials from your AWS CLI or SDK.

## Where files are written

- `~/.aws/credentials`: temporary access key, secret key, session token, and an `expiry` field.
- `~/.aws/config`: region and output format for the selected profile.
- `~/.aws/sso_token_cache.json`: cached SSO access token, reused until it expires.
- `.aws_sso_details`: local file in this folder for the default start URL and region.

## Examples

Use a specific profile name:

```bash
python aws_sso.py --profile dev
```

Force a fresh login and print export commands:

```bash
python aws_sso.py --refresh --export
```

If you select more than one account, the script writes separate profiles using the account names converted to lowercase with spaces replaced by hyphens.

## Notes

- If the current credentials are still valid, the script exits early and tells you how long they remain active.
- If you do not pass `--refresh`, the cached SSO token may avoid opening the browser again.
- The script assumes the AWS account, role, and region information fallbacks to `us-east-2` if you do not provide one.