import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
import configparser

import typer
import webbrowser
from boto3.session import Session
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError, NoCredentialsError
from rich import print
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

app = typer.Typer(help="AWS SSO login — browser once, credentials ready.")
console = Console()

CONFIG_FILE = Path(".aws_sso_details")
TOKEN_CACHE_FILE = Path.home() / ".aws" / "sso_token_cache.json"

# Short timeouts so probing regions that don't host the instance fails fast
PROBE_CONFIG = BotoConfig(connect_timeout=2, read_timeout=2, retries={"max_attempts": 1})


# ─────────────────────────────────────────
# Config
# ─────────────────────────────────────────

def _read_config() -> configparser.RawConfigParser:
    config = configparser.RawConfigParser()
    if CONFIG_FILE.exists():
        text = CONFIG_FILE.read_text().strip()
        if not text.startswith("["):
            text = "[DEFAULT]\n" + text
        config.read_string(text)
    return config


def save_config_values(**values: str) -> None:
    config = _read_config()
    for key, val in values.items():
        config.set("DEFAULT", key, val)
    with open(CONFIG_FILE, "w") as f:
        config.write(f)


def load_config() -> dict:
    config = _read_config()
    return {
        "start_url":    config.get("DEFAULT", "start_url",    fallback=None),
        "region":       config.get("DEFAULT", "region",       fallback="us-east-2"),
        "sso_region":   config.get("DEFAULT", "sso_region",   fallback=None),
        "last_account": config.get("DEFAULT", "last_account", fallback=None),
        "last_role":    config.get("DEFAULT", "last_role",    fallback=None),
    }


def save_last_choice(account_name: str, role_name: str) -> None:
    """Persist last account/role selection for next run."""
    save_config_values(last_account=account_name, last_role=role_name)


# ─────────────────────────────────────────
# Credential validity check
# ─────────────────────────────────────────

def check_current_credentials(profile: str) -> datetime | None:
    """
    Return expiry datetime if current credentials are still valid, else None.
    Reads the session token expiry from ~/.aws/credentials.
    """
    creds_path = Path.home() / ".aws" / "credentials"
    if not creds_path.exists():
        return None

    config = configparser.RawConfigParser()
    config.read(creds_path)

    section = profile
    if not config.has_section(section):
        return None

    # Try a cheap STS call to verify
    try:
        session = Session(profile_name=profile if profile != "default" else None)
        expiry_str = config.get(section, "expiry", fallback=None)

        sts = session.client("sts")
        sts.get_caller_identity()

        if expiry_str:
            return datetime.fromisoformat(expiry_str)
        return datetime.now(tz=timezone.utc)  # valid but no expiry stored
    except (ClientError, NoCredentialsError, Exception):
        return None


# ─────────────────────────────────────────
# SSO token cache (also stores the IAM IC region)
# ─────────────────────────────────────────

def load_cached_token(start_url: str) -> tuple[str, str] | None:
    """Return (access_token, sso_region) if a cached token is still valid."""
    if not TOKEN_CACHE_FILE.exists():
        return None
    try:
        data = json.loads(TOKEN_CACHE_FILE.read_text())
        if data.get("startUrl") != start_url or not data.get("ssoRegion"):
            return None
        expiry = datetime.fromisoformat(data["expiresAt"])
        if expiry > datetime.now(tz=timezone.utc):
            return data["accessToken"], data["ssoRegion"]
    except Exception:
        pass
    return None


def save_cached_token(start_url: str, sso_region: str, access_token: str, expires_in: int) -> None:
    expiry = datetime.now(tz=timezone.utc) + timedelta(seconds=expires_in - 60)
    TOKEN_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_CACHE_FILE.write_text(json.dumps({
        "startUrl":    start_url,
        "ssoRegion":   sso_region,
        "accessToken": access_token,
        "expiresAt":   expiry.isoformat(),
    }))
    TOKEN_CACHE_FILE.chmod(0o600)


# ─────────────────────────────────────────
# SSO region discovery + login (device flow)
# ─────────────────────────────────────────

def _start_device_flow(region: str, start_url: str) -> tuple[str, dict, dict]:
    """Succeeds only in the region where the IAM Identity Center instance lives."""
    client = Session(region_name=region).client("sso-oidc", config=PROBE_CONFIG)
    client_creds = client.register_client(clientName="aws-sso-cli", clientType="public")
    device_auth = client.start_device_authorization(
        clientId=client_creds["clientId"],
        clientSecret=client_creds["clientSecret"],
        startUrl=start_url,
    )
    return region, client_creds, device_auth


def discover_sso_region(start_url: str, preferred: str | None = None) -> tuple[str, dict, dict]:
    """Probe regions in parallel; return the first that accepts the start URL."""
    regions = Session().get_available_regions("sso-oidc")  # local metadata, no creds needed

    # Fast path: region found on a previous run
    if preferred in regions:
        try:
            return _start_device_flow(preferred, start_url)
        except Exception:
            pass

    candidates = [r for r in regions if r != preferred]
    pool = ThreadPoolExecutor(max_workers=len(candidates))
    try:
        futures = [pool.submit(_start_device_flow, r, start_url) for r in candidates]
        for fut in as_completed(futures):
            try:
                return fut.result()
            except Exception:
                continue
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    raise typer.BadParameter("Could not find an IAM Identity Center instance for that start URL.")


def sso_login(start_url: str, preferred_region: str | None = None, force: bool = False) -> tuple[Session, str]:
    """Returns (session bound to the SSO region, access_token)."""
    if not force:
        cached = load_cached_token(start_url)
        if cached:
            token, sso_region = cached
            print("Using cached SSO session.")
            return Session(region_name=sso_region), token

    with console.status("[bold]Locating SSO instance...[/bold]"):
        sso_region, client_creds, device_auth = discover_sso_region(start_url, preferred_region)

    save_config_values(sso_region=sso_region)
    session = Session(region_name=sso_region)
    sso_oidc = session.client("sso-oidc")  # normal timeouts for polling

    url        = device_auth["verificationUriComplete"]
    interval   = device_auth.get("interval", 5)
    expires_in = device_auth.get("expiresIn", 600)

    print(f"\n[bold medium_purple]Opening browser for SSO login...[/bold medium_purple]")
    print(f"If it doesn't open automatically:\n  {url}\n")
    webbrowser.open(url)

    with console.status("[bold yellow]Waiting for browser approval...[/bold yellow]"):
        for _ in range(expires_in // interval):
            time.sleep(interval)
            try:
                token = sso_oidc.create_token(
                    grantType="urn:ietf:params:oauth:grant-type:device_code",
                    deviceCode=device_auth["deviceCode"],
                    clientId=client_creds["clientId"],
                    clientSecret=client_creds["clientSecret"],
                )
                access_token = token["accessToken"]
                # use the token's own lifetime, not the device-code lifetime
                save_cached_token(start_url, sso_region, access_token, token.get("expiresIn", 28800))
                return session, access_token
            except sso_oidc.exceptions.AuthorizationPendingException:
                continue
            except sso_oidc.exceptions.SlowDownException:
                interval += 5
                continue

    raise typer.BadParameter("SSO login timed out. Please try again.")


# ─────────────────────────────────────────
# Account / role listing
# ─────────────────────────────────────────

def list_accounts(session: Session, access_token: str) -> list[dict]:
    sso = session.client("sso")
    paginator = sso.get_paginator("list_accounts")
    accounts = []
    for page in paginator.paginate(accessToken=access_token):
        accounts.extend(page["accountList"])
    return sorted(accounts, key=lambda a: a["accountName"].lower())


def list_roles(session: Session, access_token: str, account_id: str) -> list[str]:
    sso = session.client("sso")
    paginator = sso.get_paginator("list_account_roles")
    roles = []
    for page in paginator.paginate(accessToken=access_token, accountId=account_id):
        roles.extend(r["roleName"] for r in page["roleList"])
    return sorted(roles)


# ─────────────────────────────────────────
# Interactive selection
# ─────────────────────────────────────────

def prompt_account_selection(accounts: list[dict], last_account: str | None) -> list[dict]:
    if len(accounts) == 1:
        print(f"Only one account available: [bold]{accounts[0]['accountName']}[/bold]")
        return accounts

    table = Table(title="\nAvailable AWS Accounts", show_lines=True)
    table.add_column("#", style="bold medium_purple", width=4)
    table.add_column("Account Name", style="white")
    table.add_column("Account ID", style="dim")

    default_idx = None
    for i, acc in enumerate(accounts, 1):
        marker = " [medium_purple]← last[/medium_purple]" if acc["accountName"] == last_account else ""
        table.add_row(str(i), acc["accountName"] + marker, acc["accountId"])
        if acc["accountName"] == last_account:
            default_idx = i

    console.print(table)

    prompt_suffix = f" (Enter for {default_idx})" if default_idx else ""
    raw = typer.prompt(f"\nSelect account(s) (e.g. 1 or 1,3,5){prompt_suffix}", default="")

    if not raw and default_idx:
        raw = str(default_idx)

    try:
        indexes = [int(x.strip()) - 1 for x in raw.split(",")]
        return [accounts[i] for i in indexes]
    except (ValueError, IndexError):
        raise typer.BadParameter("Invalid selection.")


def prompt_role_selection(roles: list[str], account_name: str, last_role: str | None) -> str:
    if not roles:
        raise typer.BadParameter(f"No roles found for '{account_name}'.")

    if len(roles) == 1:
        print(f"Using only available role: [bold]{roles[0]}[/bold]")
        return roles[0]

    print(f"\n[bold medium_purple]Roles for {account_name}:[/bold medium_purple]")
    default_idx = None
    for i, role in enumerate(roles, 1):
        marker = " [medium_purple]← last[/medium_purple]" if role == last_role else ""
        print(f"  {i}) {role}{marker}")
        if role == last_role:
            default_idx = i

    prompt_suffix = f" (Enter for {default_idx})" if default_idx else ""
    raw = typer.prompt(f"Select role{prompt_suffix}", default="")

    if not raw and default_idx:
        raw = str(default_idx)

    try:
        return roles[int(raw.strip()) - 1]
    except (ValueError, IndexError):
        raise typer.BadParameter("Invalid role selection.")


# ─────────────────────────────────────────
# Fetch & write credentials
# ─────────────────────────────────────────

def get_role_credentials(
    session: Session, access_token: str, account_id: str, role_name: str
) -> dict:
    sso = session.client("sso")
    resp = sso.get_role_credentials(
        accessToken=access_token,
        accountId=account_id,
        roleName=role_name,
    )
    return resp["roleCredentials"]


def write_credentials(creds: dict, region: str, profile: str = "default") -> None:
    credentials_path = Path.home() / ".aws" / "credentials"
    config_path      = Path.home() / ".aws" / "config"
    credentials_path.parent.mkdir(parents=True, exist_ok=True)

    expiry = datetime.fromtimestamp(creds["expiration"] / 1000, tz=timezone.utc)

    cred_cfg = configparser.RawConfigParser()
    cred_cfg.read(credentials_path)
    if not cred_cfg.has_section(profile):
        cred_cfg.add_section(profile)
    cred_cfg.set(profile, "aws_access_key_id",     creds["accessKeyId"])
    cred_cfg.set(profile, "aws_secret_access_key", creds["secretAccessKey"])
    cred_cfg.set(profile, "aws_session_token",     creds["sessionToken"])
    cred_cfg.set(profile, "expiry",                expiry.isoformat())
    with open(credentials_path, "w") as f:
        cred_cfg.write(f)

    cfg_section = "default" if profile == "default" else f"profile {profile}"
    cfg = configparser.RawConfigParser()
    cfg.read(config_path)
    if not cfg.has_section(cfg_section):
        cfg.add_section(cfg_section)
    cfg.set(cfg_section, "region", region)
    cfg.set(cfg_section, "output", "json")
    with open(config_path, "w") as f:
        cfg.write(f)



# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────

@app.command()
def main(
    start_url: str  = typer.Option(None,      "--start-url", "-u",  help="AWS SSO start URL"),
    region:    str  = typer.Option(None,      "--region",    "-r",  help="Region for the credentials/config"),
    profile:   str  = typer.Option("default", "--profile",   "-p",  help="~/.aws/credentials profile to write"),
    refresh:   bool = typer.Option(False,     "--refresh",   "-re", help="Force full re-authentication (opens browser)"),
    switch:    bool = typer.Option(False,     "--switch",    "-s",  help="List accounts again and switch account/role"),
):
    """Log in to AWS SSO and write short-term credentials — no second login needed."""
    cfg = load_config()
    start_url = start_url or cfg["start_url"]
    region    = region    or cfg["region"]

    if not start_url:
        raise typer.BadParameter("Missing start_url. Pass --start-url or add to .aws_sso_details.")

    # ── Skip everything if credentials are still fresh (unless switching) ───
    if not refresh and not switch:
        expiry = check_current_credentials(profile)
        if expiry:
            remaining = expiry - datetime.now(tz=timezone.utc)
            hours, rem = divmod(int(remaining.total_seconds()), 3600)
            minutes = rem // 60
            print(f"\n[bold medium_purple]✓ Credentials still valid[/bold medium_purple] — expires in "
                  f"[bold]{hours}h {minutes}m[/bold] "
                  f"({expiry.astimezone().strftime('%H:%M %Z')})")
            print("Run with --switch to change account/role, or --refresh to re-authenticate.\n")
            raise typer.Exit()

    # ── SSO login (uses token cache when available; discovers IC region) ────
    session, access_token = sso_login(start_url, cfg["sso_region"], force=refresh)

    with console.status("[bold]Fetching accounts...[/bold]"):
        accounts = list_accounts(session, access_token)

    if not accounts:
        print("[bold red]No AWS accounts found for this SSO session.[/bold red]")
        raise typer.Exit(code=1)

    selected = prompt_account_selection(accounts, cfg["last_account"])

    for acc in selected:
        with console.status(f"[bold]Fetching roles for {acc['accountName']}...[/bold]"):
            roles = list_roles(session, access_token, acc["accountId"])

        role_name = prompt_role_selection(roles, acc["accountName"], cfg["last_role"])

        with console.status("[bold]Fetching credentials...[/bold]"):
            creds = get_role_credentials(session, access_token, acc["accountId"], role_name)

        dest_profile = profile if len(selected) == 1 else acc["accountName"].lower().replace(" ", "-")
        write_credentials(creds, region, dest_profile)

        expiry     = datetime.fromtimestamp(creds["expiration"] / 1000, tz=timezone.utc).astimezone()
        expiry_str = expiry.strftime("%H:%M %Z")
        remaining  = expiry - datetime.now(tz=timezone.utc)
        hours, rem = divmod(int(remaining.total_seconds()), 3600)

        print(f"\n[bold medium_purple]✓[/bold medium_purple] [bold]{acc['accountName']}[/bold] "
              f"· role [medium_purple]{role_name}[/medium_purple] "
              f"· profile [medium_purple]{dest_profile}[/medium_purple] "
              f"· expires {expiry_str} ({hours}h {rem // 60}m)")

        save_last_choice(acc["accountName"], role_name)

    print()


if __name__ == "__main__":
    app()