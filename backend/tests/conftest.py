import sys
from pathlib import Path

# Add /app to sys.path so `from scanner.vuln import ...` works from anywhere
_APP_ROOT = Path(__file__).resolve().parents[2]
if str(_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(_APP_ROOT))
