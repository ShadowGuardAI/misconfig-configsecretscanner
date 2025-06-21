# misconfig-ConfigSecretScanner
Scans configuration files for embedded secrets (API keys, passwords, etc.) using regex patterns and entropy analysis. Leverages libraries like `secrets` and `regex` to identify potentially exposed credentials. - Focused on Check for misconfigurations in configuration files or infrastructure definitions

## Install
`git clone https://github.com/ShadowGuardAI/misconfig-configsecretscanner`

## Usage
`./misconfig-configsecretscanner [params]`

## Parameters
- `-h`: Show help message and exit
- `-r`: Recursively scan directories.
- `-e`: List of directories or files to exclude from the scan.
- `-v`: Enable verbose output.
- `-j`: Path to save JSON output.

## License
Copyright (c) ShadowGuardAI
