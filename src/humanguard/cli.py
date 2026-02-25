import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import random
import re

app = typer.Typer(help="HumanGuard: Your Personal Digital Safety Assistant")
console = Console()

TIPS = [
    "Never click on links in unsolicited emails or SMS messages.",
    "Enable Multi-Factor Authentication (MFA) on all your important accounts.",
    "Use a password manager to generate and store unique, strong passwords.",
    "Be wary of 'urgent' requests for money or sensitive information.",
    "Hover over links to see the actual destination URL before clicking.",
    "Keep your software and operating system updated to patch security holes.",
    "Public Wi-Fi is not secure. Use a VPN or your mobile data for sensitive tasks.",
]

PHISHING_KEYWORDS = [
    "urgent", "action required", "account suspended", "verify", "password reset",
    "login now", "gift card", "lottery", "winner", "bank", "unauthorized",
    "security alert", "official", "immediate", "prize"
]

@app.command()
def tip():
    """Get a daily digital safety tip."""
    tip = random.choice(TIPS)
    console.print(Panel(f"[bold green]🛡️ Daily Safety Tip:[/bold green]\n\n{tip}", expand=False))

@app.command()
def check(text: str):
    """Analyze a message for social engineering/phishing indicators."""
    console.print(f"\n[bold yellow]Analyzing message...[/bold yellow]\n")
    
    found = []
    text_lower = text.lower()
    
    for kw in PHISHING_KEYWORDS:
        if kw in text_lower:
            found.append(kw)
            
    # Heuristic score
    score = len(found)
    if any(x in text_lower for x in ["http", "https", "click here", ".com"]):
        score += 2

    table = Table(title="Analysis Report")
    table.add_column("Indicator", style="cyan")
    table.add_column("Result", style="magenta")
    
    table.add_row("Suspicious Keywords", ", ".join(found) if found else "None")
    table.add_row("Urgency Tone", "Yes" if any(x in text_lower for x in ["urgent", "immediate", "now"]) else "No")
    
    status = "[bold red]HIGH RISK[/bold red]" if score > 3 else "[bold yellow]MEDIUM RISK[/bold yellow]" if score > 1 else "[bold green]LOW RISK[/bold green]"
    table.add_row("Overall Risk Level", status)
    
    console.print(table)
    
    if score > 0:
        console.print("\n[bold red]Advice:[/bold red] This message looks suspicious. Do not click links or provide info.")

@app.command()
def url(link: str):
    """Check a URL for common malicious patterns."""
    console.print(f"Checking URL: [blue]{link}[/blue]")
    
    suspicious = False
    reasons = []
    
    # Check for IP address in URL
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', link):
        suspicious = True
        reasons.append("Contains raw IP address instead of domain name.")
        
    # Check for too many subdomains
    if link.count('.') > 3:
        suspicious = True
        reasons.append("Too many subdomains (often used for spoofing).")
        
    # Check for suspicious keywords in domain
    if any(kw in link.lower() for kw in ["login", "secure", "verify", "update", "signin"]):
        suspicious = True
        reasons.append("Contains sensitive keywords in URL path/domain.")

    if suspicious:
        console.print(f"\n[bold red]⚠️  WARNING:[/bold red] This URL looks suspicious!")
        for r in reasons:
            console.print(f"- {r}")
    else:
        console.print("\n[bold green]✅ URL appears to follow normal patterns.[/bold green]")

@app.command()
def pwd(password: str = typer.Option(..., prompt=True, hide_input=True)):
    """Check password strength locally (no data sent to server)."""
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    score = 0
    if length >= 8: score += 1
    if length >= 12: score += 1
    if has_upper: score += 1
    if has_lower: score += 1
    if has_digit: score += 1
    if has_special: score += 1
    
    results = [
        ("Length >= 8", "✅" if length >= 8 else "❌"),
        ("Uppercase", "✅" if has_upper else "❌"),
        ("Lowercase", "✅" if has_lower else "❌"),
        ("Numbers", "✅" if has_digit else "❌"),
        ("Symbols", "✅" if has_special else "❌"),
    ]
    
    table = Table(title="Password Strength Check")
    table.add_column("Criteria")
    table.add_column("Result")
    for c, r in results:
        table.add_row(c, r)
        
    console.print(table)
    
    if score >= 5:
        console.print("[bold green]Strength: Strong[/bold green]")
    elif score >= 3:
        console.print("[bold yellow]Strength: Moderate[/bold yellow]")
    else:
        console.print("[bold red]Strength: Weak[/bold red]")

if __name__ == "__main__":
    app()
