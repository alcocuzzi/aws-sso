import time
import json
from datetime import datetime, timezone
from pathlib import Path
import configparser

import typer
import webbrowser
from boto3.session import Session
from botocore.exceptions import ClientError, NoCredentialsError
from rich import print
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

app = typer.Typer(help="AWS SSO login — browser once, credentials ready.")
console = Console()

CONFIG_FILE = Path(".aws_sso_details")
TOKEN_CACHE_FILE = Path.home() / ".aws" / "sso_token_cache.json"


# ─────────────────────────────────────────
# Config
# ─────────────────────────────────────────

def load_config() -> dict:
    config = configparser.RawConfigParser()
    if CONFIG_FILE.exists():
        text = CONFIG_FILE.read_text().strip()
        if not text.startswith("["):
            text = "[DEFAULT]\n" + text
        config.read_string(text)

    return {
        "start_url":    config.get("DEFAULT", "start_url",    fallback=None),
        "region":       config.get("DEFAULT", "region",       fallback="us-east-1"),
        "last_account": config.get("DEFAULT", "last_account", fallback=None),
        "last_role":    config.get("DEFAULT", "last_role",    fallback=None),
    }


def save_last_choice(account_name: str, role_name: str) -> None:
    """Persist last account/role selection for next run."""
    config = configparser.RawConfigParser()
    if CONFIG_FILE.exists():
        text = CONFIG_FILE.read_text().strip()
        if not text.startswith("["):
            text = "[DEFAULT]\n" + text
        config.read_string(text)

    config.set("DEFAULT", "last_account", account_name)
    config.set("DEFAULT", "last_role", role_name)

    with open(CONFIG_FILE, "w") as f:
        config.write(f)


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
# SSO token cache
# ─────────────────────────────────────────

def load_cached_token(start_url: str) -> str | None:
    """Return a cached SSO access token if still valid."""
    if not TOKEN_CACHE_FILE.exists():
        return None
    try:
        data = json.loads(TOKEN_CACHE_FILE.read_text())
        if data.get("startUrl") != start_url:
            return None
        expiry = datetime.fromisoformat(data["expiresAt"])
        if expiry > datetime.now(tz=timezone.utc):
            return data["accessToken"]
    except Exception:
        pass
    return None


def save_cached_token(start_url: str, access_token: str, expires_in: int) -> None:
    from datetime import timedelta
    expiry = datetime.now(tz=timezone.utc) + timedelta(seconds=expires_in - 60)
    TOKEN_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_CACHE_FILE.write_text(json.dumps({
        "startUrl":    start_url,
        "accessToken": access_token,
        "expiresAt":   expiry.isoformat(),
    }))
    TOKEN_CACHE_FILE.chmod(0o600)


# ─────────────────────────────────────────
# SSO login (device flow)
# ─────────────────────────────────────────

def sso_login(region: str, start_url: str, force: bool = False) -> tuple[Session, str]:
    session = Session(region_name=region)

    if not force:
        cached = load_cached_token(start_url)
        if cached:
            print("[dim]Using cached SSO session (no browser needed).[/dim]")
            return session, cached

    sso_oidc = session.client("sso-oidc")

    client_creds = sso_oidc.register_client(
        clientName="aws-sso-cli",
        clientType="public",
    )

    device_auth = sso_oidc.start_device_authorization(
        clientId=client_creds["clientId"],
        clientSecret=client_creds["clientSecret"],
        startUrl=start_url,
    )

    url      = device_auth["verificationUriComplete"]
    interval = device_auth.get("interval", 5)
    expires_in = device_auth.get("expiresIn", 600)

    print(f"\n[bold green]Opening browser for SSO login...[/bold green]")
    print(f"[dim]If it doesn't open automatically:[/dim]\n  {url}\n")
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
                save_cached_token(start_url, access_token, expires_in)
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
        print(f"[dim]Only one account available:[/dim] [bold]{accounts[0]['accountName']}[/bold]")
        return accounts

    table = Table(title="\nAvailable AWS Accounts", show_lines=True)
    table.add_column("#", style="bold cyan", width=4)
    table.add_column("Account Name", style="white")
    table.add_column("Account ID", style="dim")

    default_idx = None
    for i, acc in enumerate(accounts, 1):
        marker = " [green]← last[/green]" if acc["accountName"] == last_account else ""
        table.add_row(str(i), acc["accountName"] + marker, acc["accountId"])
        if acc["accountName"] == last_account:
            default_idx = i

    console.print(table)

    prompt_suffix = f" [dim](Enter for {default_idx})[/dim]" if default_idx else ""
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
        print(f"[dim]Using only available role:[/dim] [bold]{roles[0]}[/bold]")
        return roles[0]

    print(f"\n[bold cyan]Roles for {account_name}:[/bold cyan]")
    default_idx = None
    for i, role in enumerate(roles, 1):
        marker = " [green]← last[/green]" if role == last_role else ""
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


def print_export_snippet(creds: dict, region: str) -> None:
    """Print shell export lines — useful for subshells or piping."""
    lines = [
        f'export AWS_ACCESS_KEY_ID="{creds["accessKeyId"]}"',
        f'export AWS_SECRET_ACCESS_KEY="{creds["secretAccessKey"]}"',
        f'export AWS_SESSION_TOKEN="{creds["sessionToken"]}"',
        f'export AWS_DEFAULT_REGION="{region}"',
    ]
    panel_content = "\n".join(lines)
    console.print(Panel(panel_content, title="[bold]Export snippet[/bold]", border_style="dim"))


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────

@app.command()
def main(
    start_url: str  = typer.Option(None,      "--start-url", "-u",  help="AWS SSO start URL"),
    region:    str  = typer.Option(None,      "--region",    "-r",  help="AWS region"),
    profile:   str  = typer.Option("default", "--profile",   "-p",  help="~/.aws/credentials profile to write"),
    export:    bool = typer.Option(False,     "--export",    "-e",  help="Also print export AWS_* lines"),
    refresh:   bool = typer.Option(False,     "--refresh",          help="Force re-auth even if credentials are valid"),
):
    """Log in to AWS SSO and write short-term credentials — no second login needed."""
    cfg = load_config()
    start_url = start_url or cfg["start_url"]
    region    = region    or cfg["region"]

    if not start_url:
        raise typer.BadParameter("Missing start_url. Pass --start-url or add to .aws_sso_details.")

    # ── Skip everything if credentials are still fresh ──────────────────────
    if not refresh:
        expiry = check_current_credentials(profile)
        if expiry:
            remaining = expiry - datetime.now(tz=timezone.utc)
            hours, rem = divmod(int(remaining.total_seconds()), 3600)
            minutes = rem // 60
            print(f"\n[bold green]✓ Credentials still valid[/bold green] — expires in "
                  f"[bold]{hours}h {minutes}m[/bold] "
                  f"[dim]({expiry.astimezone().strftime('%H:%M %Z')})[/dim]")
            print("[dim]Run with --refresh to force re-authentication.[/dim]\n")
            raise typer.Exit()

    # ── SSO login (uses token cache when available) ──────────────────────────
    session, access_token = sso_login(region, start_url, force=refresh)

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

        print(f"\n[bold green]✓[/bold green] [bold]{acc['accountName']}[/bold] "
              f"· role [cyan]{role_name}[/cyan] "
              f"· profile [cyan]{dest_profile}[/cyan] "
              f"· expires [dim]{expiry_str} ({hours}h {rem // 60}m)[/dim]")

        if export:
            print_export_snippet(creds, region)

        save_last_choice(acc["accountName"], role_name)

    print()


if __name__ == "__main__":
    app()
