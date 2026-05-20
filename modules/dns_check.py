import dns.resolver
from rich.console import Console
from rich.table import Table

console = Console()

def check_dns(domain):
    console.print(f"\n[bold cyan]🔍 DNS Records for {domain}[/bold cyan]")
    results = {
        "mx_records": [],
        "spf": None,
        "dmarc": None,
        "spf_found": False,
        "dmarc_found": False
    }

    # MX Records
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        table = Table(title="MX Records (Mail Servers)", style="cyan")
        table.add_column("Priority", style="yellow")
        table.add_column("Mail Server", style="green")
        for record in mx_records:
            entry = {"priority": str(record.preference), "server": str(record.exchange)}
            results["mx_records"].append(entry)
            table.add_row(entry["priority"], entry["server"])
        console.print(table)
    except Exception:
        console.print("[red]❌ No MX records found[/red]")

    # SPF
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        for record in txt_records:
            record_str = str(record)
            if 'v=spf1' in record_str:
                results["spf"] = record_str
                results["spf_found"] = True
                console.print(f"\n[bold green]✅ SPF Record Found:[/bold green]")
                console.print(f"[white]{record_str}[/white]")
        if not results["spf_found"]:
            console.print("\n[red]❌ No SPF record found — domain may be spoofable![/red]")
    except Exception:
        console.print("[red]❌ Could not retrieve TXT records[/red]")

    # DMARC
    try:
        dmarc = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for record in dmarc:
            results["dmarc"] = str(record)
            results["dmarc_found"] = True
            console.print(f"\n[bold green]✅ DMARC Record Found:[/bold green]")
            console.print(f"[white]{str(record)}[/white]")
    except Exception:
        console.print("\n[red]❌ No DMARC record — phishing protection missing![/red]")

    return results