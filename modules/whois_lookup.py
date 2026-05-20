import whois
from rich.console import Console
from rich.table import Table
from datetime import datetime, timezone

console = Console()

def check_whois(domain):
    console.print(f"\n[bold cyan]🌐 WHOIS Lookup for {domain}[/bold cyan]")
    results = {
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "name_servers": None,
        "org": None,
        "country": None,
        "age_days": None,
        "is_new": False
    }

    try:
        w = whois.whois(domain)

        def fmt(val):
            if val is None:
                return None
            if isinstance(val, list):
                val = val[0]
            if isinstance(val, datetime):
                return val.strftime("%Y-%m-%d %H:%M:%S")
            return str(val)

        results["registrar"]        = fmt(w.registrar)
        results["creation_date"]    = fmt(w.creation_date)
        results["expiration_date"]  = fmt(w.expiration_date)
        results["updated_date"]     = fmt(w.updated_date)
        results["name_servers"]     = fmt(w.name_servers)
        results["org"]              = fmt(w.org)
        results["country"]          = fmt(w.country)

        table = Table(style="cyan")
        table.add_column("Field", style="yellow", width=20)
        table.add_column("Value", style="white")
        for k, v in results.items():
            if k not in ("age_days", "is_new") and v:
                table.add_row(k.replace("_", " ").title(), v)
        console.print(table)

        if w.creation_date:
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - created).days
            results["age_days"] = age_days
            results["is_new"] = age_days < 180
            if results["is_new"]:
                console.print(f"[bold red]⚠️  Domain is only {age_days} days old — possible phishing domain![/bold red]")
            else:
                console.print(f"[green]✅ Domain is {age_days} days old — looks established[/green]")

    except Exception as e:
        console.print(f"[red]❌ WHOIS lookup failed: {e}[/red]")

    return results