# NetConfigPro

A network configuration generator and validator for network engineers.

## Features

- **Multi-vendor support**: Generate configurations for Cisco IOS/IOS-XE, NX-OS, Arista EOS, and Juniper Junos
- **Configuration validation**: Catch errors and get best-practice recommendations before deployment
- **Import & analyze**: Parse existing configurations and identify issues
- **Secure vault**: Encrypted storage for credentials and sensitive variables
- **Modern GUI**: Clean, dark-themed interface using CustomTkinter

## Installation

```bash
# Clone the repository
cd netconfigpro

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Run the application
python main.py
```

### Quick Start

1. **Generate Configuration**
   - Select your target vendor
   - Fill in hostname, interfaces, VLANs, routing configuration
   - Click "Generate Configuration"
   - Review validation results and export

2. **Import Configuration**
   - Paste an existing configuration or open a file
   - Click "Parse Configuration"
   - Review parsed elements and validation issues

3. **Secure Vault**
   - Create a vault with a master password
   - Store credentials and template variables securely
   - All data is encrypted at rest

## Supported Configuration Elements

| Element | Cisco IOS | NX-OS | Arista EOS | Juniper |
|---------|-----------|-------|------------|---------|
| Interfaces | Yes | Yes | Yes | Yes |
| VLANs | Yes | Yes | Yes | Yes |
| ACLs | Yes | Yes | Yes | Yes |
| Static Routes | Yes | Yes | Yes | Yes |
| OSPF | Yes | Yes | Yes | Yes |
| BGP | Yes | Yes | Yes | Yes |

## Project Structure

```
netconfigpro/
├── main.py              # Application entry point
├── requirements.txt     # Python dependencies
├── src/
│   ├── core/            # Business logic
│   │   ├── models.py    # Data models
│   │   ├── generators/  # Config generation
│   │   ├── validators/  # Validation rules
│   │   ├── parsers/     # Config parsing
│   │   └── templates/   # Vendor-specific templates
│   ├── security/        # Encryption, vault
│   ├── gui/             # CustomTkinter GUI
│   └── utils/           # Utility functions
├── tests/               # Test suite
├── data/                # Application data
└── docs/                # Documentation
```

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=src
```

## Security

- All sensitive data is encrypted using AES-256 (Fernet)
- PBKDF2 with 480,000 iterations for key derivation
- Vault files use restrictive permissions (600)
- No plaintext secrets stored on disk

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+N | New configuration |
| Ctrl+O | Open file |
| Ctrl+H | Help |
| F1 | Help |
| Ctrl+Q | Quit |

## Requirements

- Python 3.10+
- customtkinter
- Jinja2
- cryptography
- PyYAML

## License

MIT License
