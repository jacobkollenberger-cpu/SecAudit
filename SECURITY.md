# Security Notes

**Use this responsibly.** The `--remote` scanning feature makes real TCP connection attempts against whatever host you point it at. Only run it against machines you own or have explicit permission to test - your own computer, a lab VM, the Terraform lab in this repo, etc. Scanning something you don't have permission for can be illegal (the Computer Fraud and Abuse Act in the US) and will almost certainly violate whoever's hosting it's terms of service.

If you find an actual security bug in this tool itself (not a scanning-target finding, but something wrong with SecAudit's own code), feel free to open an issue or reach out directly.
