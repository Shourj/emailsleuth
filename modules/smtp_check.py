import smtplib
import dns.resolver
from rich.console import Console

console = Console()

def check_smtp(email):
    console.print(f"\n[bold cyan]📨 SMTP Validation for {email}[/bold cyan]")
    domain = email.split('@')[1]
    results = {
        "mx_host": None,
        "status": "unknown",
        "message": None
    }

    try:
        mx_records = sorted(
            dns.resolver.resolve(domain, 'MX'),
            key=lambda x: x.preference
        )
        results["mx_host"] = str(mx_records[0].exchange).rstrip('.')
        console.print(f"[dim]Connecting to: {results['mx_host']}[/dim]")

        with smtplib.SMTP(timeout=10) as smtp:
            smtp.connect(results["mx_host"], 25)
            smtp.helo("check.example.com")
            smtp.mail("probe@example.com")
            code, message = smtp.rcpt(email)

            if code == 250:
                results["status"] = "exists"
                results["message"] = "Email address exists on the mail server"
                console.print("[bold green]✅ Email address EXISTS[/bold green]")
            elif code == 550:
                results["status"] = "not_found"
                results["message"] = "Email address does not exist"
                console.print("[bold red]❌ Email address DOES NOT EXIST[/bold red]")
            else:
                results["status"] = "inconclusive"
                results["message"] = f"Server responded with code {code}"
                console.print(f"[yellow]⚠️  Inconclusive — code {code}[/yellow]")
            smtp.quit()

    except smtplib.SMTPConnectError:
        results["status"] = "blocked"
        results["message"] = "Port 25 blocked (common on home networks)"
        console.print("[yellow]⚠️  Could not connect — port 25 may be blocked[/yellow]")
    except Exception as e:
        results["status"] = "inconclusive"
        results["message"] = str(e)
        console.print(f"[yellow]⚠️  SMTP check inconclusive: {e}[/yellow]")

    return results