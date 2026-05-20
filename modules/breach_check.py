import requests
import hashlib
from rich.console import Console
from rich.table import Table

console = Console()

def check_breaches(email):
    console.print(f"\n[bold cyan]🔓 Breach Check for {email}[/bold cyan]")
    domain = email.split('@')[1]
    results = {
        "hash_found": False,
        "hash_count": 0,
        "is_disposable": False,
        "leakcheck_found": False,
        "leakcheck_count": 0,
        "leakcheck_sources": []
    }

    # k-Anonymity hash check
    console.print("\n[dim]Checking email hash against breach databases...[/dim]")
    try:
        sha1 = hashlib.sha1(email.lower().encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        r = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "EmailOSINTToolkit"},
            timeout=10
        )
        for line in r.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                results["hash_found"] = True
                results["hash_count"] = int(count)
                console.print(f"[bold red]⚠️  Email hash seen {count} times in breach dumps![/bold red]")
                break
        if not results["hash_found"]:
            console.print("[green]✅ Email hash not found in known breach dumps[/green]")
    except Exception as e:
        console.print(f"[red]❌ Hash check failed: {e}[/red]")

    # Disposable check
    try:
        r = requests.get(
            "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf",
            timeout=10
        )
        if domain.lower() in r.text.splitlines():
            results["is_disposable"] = True
            console.print(f"[bold red]🚨 '{domain}' is a DISPOSABLE email domain![/bold red]")
        else:
            console.print(f"[green]✅ '{domain}' is not a known disposable email service[/green]")
    except Exception as e:
        console.print(f"[yellow]⚠️  Disposable check failed: {e}[/yellow]")

    # LeakCheck
    try:
        r = requests.get(
            f"https://leakcheck.io/api/public?check={email}",
            headers={"User-Agent": "EmailOSINTToolkit"},
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("found", 0) > 0:
                results["leakcheck_found"] = True
                results["leakcheck_count"] = data["found"]
                results["leakcheck_sources"] = data.get("sources", [])
                console.print(f"\n[bold red]🚨 Found in {data['found']} breach(es) via LeakCheck![/bold red]")
                table = Table(title="Breach Sources", style="red")
                table.add_column("Source", style="yellow")
                table.add_column("Date", style="white")
                for s in results["leakcheck_sources"]:
                    table.add_row(s.get("name", "Unknown"), s.get("date", "Unknown"))
                console.print(table)
            else:
                console.print("[green]✅ Not found in LeakCheck public breach database[/green]")
    except Exception as e:
        console.print(f"[yellow]⚠️  LeakCheck failed: {e}[/yellow]")

    return results