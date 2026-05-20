import hashlib
import requests
from rich.console import Console

console = Console()

def check_gravatar(email):
    console.print(f"\n[bold cyan]👤 Gravatar OSINT for {email}[/bold cyan]")
    email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
    results = {
        "hash": email_hash,
        "avatar_exists": False,
        "avatar_url": None,
        "display_name": None,
        "full_name": None,
        "location": None,
        "bio": None,
        "profile_url": None,
        "linked_accounts": [],
        "urls": []
    }

    avatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
    try:
        r = requests.get(avatar_url, timeout=10)
        if r.status_code == 200:
            results["avatar_exists"] = True
            results["avatar_url"] = f"https://www.gravatar.com/avatar/{email_hash}?s=200"
            console.print(f"[bold green]✅ Gravatar avatar EXISTS[/bold green]")
            console.print(f"[dim]Avatar:[/dim] {results['avatar_url']}")
        else:
            console.print("[yellow]⚠️  No Gravatar avatar found[/yellow]")
            return results
    except Exception as e:
        console.print(f"[red]❌ Avatar check failed: {e}[/red]")
        return results

    try:
        r = requests.get(f"https://www.gravatar.com/{email_hash}.json", timeout=10)
        if r.status_code == 200:
            entry = r.json().get("entry", [{}])[0]
            results["display_name"] = entry.get("displayName")
            results["full_name"]    = entry.get("name", {}).get("formatted")
            results["location"]     = entry.get("currentLocation")
            results["bio"]          = entry.get("aboutMe")
            results["profile_url"]  = entry.get("profileUrl")
            results["linked_accounts"] = entry.get("accounts", [])
            results["urls"]         = entry.get("urls", [])
            console.print(f"[bold green]✅ Public profile found![/bold green]")
            for k in ("display_name", "full_name", "location", "bio", "profile_url"):
                if results[k]:
                    console.print(f"[yellow]{k.replace('_',' ').title()}:[/yellow] {results[k]}")
    except Exception as e:
        console.print(f"[red]❌ Profile fetch failed: {e}[/red]")

    return results