from rich.console import Console
from rich.panel import Panel
from modules.dns_check import check_dns
from modules.whois_lookup import check_whois
from modules.breach_check import check_breaches
from modules.smtp_check import check_smtp
from modules.gravatar_check import check_gravatar
from modules.report_generator import generate_report

console = Console()

def get_domain(email):
    return email.split('@')[1]

def main():
    console.print(Panel.fit(
        "[bold green]EmailSleuth — Email OSINT Toolkit[/bold green]\n[dim]by You[/dim]",
        border_style="green"
    ))

    email = input("\nEnter target email: ").strip()

    if '@' not in email:
        console.print("[red]Invalid email address![/red]")
        return

    domain = get_domain(email)
    console.print(f"\n[dim]Extracted domain:[/dim] [bold]{domain}[/bold]")

    data = {
        "email":    email,
        "domain":   domain,
        "dns":      check_dns(domain),
        "whois":    check_whois(domain),
        "breach":   check_breaches(email),
        "smtp":     check_smtp(email),
        "gravatar": check_gravatar(email),
    }

    console.print("\n[bold green]✅ Scan complete! Generating report...[/bold green]")
    filename = generate_report(data)
    console.print(f"\n[bold cyan]📄 Report saved:[/bold cyan] [white]{filename}[/white]")
    console.print("[dim]Open it in your browser to view the full report.[/dim]")

if __name__ == "__main__":
    main()