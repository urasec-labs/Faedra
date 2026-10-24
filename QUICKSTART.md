# Faedra Pro — Quick Start

**Author:** Uras AKAS | urasakas.com

## 1. Install

```bash
cd Faedra-Pro
pip install -r requirements.txt

# Optional system tools (recommended)
# sudo apt install nmap
# go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# go install github.com/ffuf/ffuf/v2@latest
```

## 2. Basic Usage

```bash
# List modules
python faedra.py modules

# Quick passive + light recon
python faedra.py recon example.com

# Bug bounty oriented profile
python faedra.py full example.com --profile bugbounty

# Deep assessment (authorized targets only)
python faedra.py full example.com --profile deep --no-safe

# Continuous monitoring
python faedra.py monitor example.com --interval 24
```

## 3. Profiles

| Profile    | Modules |
|------------|---------|
| `quick`    | passive_recon, asset_inventory, osint_footprint |
| `bugbounty`| passive_recon, asset_inventory, bug_bounty, osint_footprint, ai_analysis, notification |
| `deep`     | Almost everything (active modules included) |
| `monitor`  | passive_recon + asset_inventory + notification |

## 4. Configuration

Edit `config/default.yaml` for:
- API keys (Shodan, Censys, etc.)
- Notification webhooks
- Stealth / proxy settings
- Module enablement

## 5. Important

- **Safe Mode is ON by default**
- Only scan systems you are authorized to test
- See `DISCLAIMER.md`
