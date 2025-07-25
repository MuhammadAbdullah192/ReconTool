from pyfiglet import Figlet
from rich.console import Console
from rich.panel import Panel

console = Console()
figlet = Figlet(font='slant')  # You can also try 'standard', 'block', 'doom', etc.
banner_text = figlet.renderText("Shadow X")

console.print(Panel.fit(banner_text, title="🔥 Recon Tool 🔥", subtitle="Version 1.0", style="bold green"))
