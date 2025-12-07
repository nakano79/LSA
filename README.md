# LSA (Linux Security Audit) Tool

## Description
**LSA (Linux Security Audit)** is a simple and lightweight security auditing tool designed for Linux systems. Written in Python, it automatically checks various system configurations and reports potential security vulnerabilities.

Key features include:
- **Port Scan Analysis**: Checks for open ports and specifically flags insecure well-known ports (e.g., Telnet).
- **Account Vulnerability Analysis**: Checks for root privileges, empty passwords, and UID 0 accounts.
- **Remote Access (SSH) Analysis**: Audits `sshd_config` for risky settings like root login permission or Protocol 1 usage.
- **Package & OS Patch Analysis**: Detects the OS distribution (Debian/Ubuntu or RHEL/CentOS) and checks for available updates.
- **Firewall Analysis**: Checks the status of UFW, Firewalld, or Iptables.
- **Directory Analysis**: Scans critical directories for unsafe write permissions (including sticky bit checks for `/tmp`).

## Operating Environment
- **Operating System**: Linux (Debian/Ubuntu, RHEL/CentOS/Fedora supported for package checks; general checks work on most distros).
- **Language**: Python 3.
- **Dependencies**: Standard Python libraries (`os`, `sys`, `socket`, `subprocess`, etc.). No external pip packages are required.
- **Privileges**: Root permissions (`sudo`) are recommended for full functionality (e.g., reading `/etc/shadow`, checking all listening ports).

## How to Run & Results

### How to Run
Run the script using Python 3. You can optionally specify a language code.

1.  **Auto-detect language** (checks system locale, then environmental variables, defaults to English):
    ```bash
    sudo python3 LSA.py
    ```

2.  **Specify a language** (e.g., Korean `ko`, English `en`):
    ```bash
    sudo python3 LSA.py ko
    sudo python3 LSA.py en
    ```

### Results
- The tool automatically creates a `log/` directory in the same folder as the script.
- Reports are saved as text files with a timestamp:
  `security_audit_report_YYYYMMDD_HHMMSS.txt`

## Customizing Language Files
The tool supports multi-language output using external text files.
English and Korean files are provided by default.(ko.txt, en.txt)

### Structure
Language files are named `<lang_code>.txt` (e.g., `en.txt`, `ko.txt`).
Each line follows the `KEY=VALUE` format.

**Example (`en.txt`):**
```properties
START_MSG=Starting Security Audit at
PORT_HEADER=--- Port Scan Analysis ---
PORT_SPECIFIC_OPEN=WARNING: Port {} ({}) is OPEN!
```

### How to Add/Customize
1.  **Create a new file**: Create a file named `ja.txt` (for Japanese) or any other code.
2.  **Add keys**: Copy the keys from `en.txt` and translate the values.
3.  **Placeholders**: Keep Python format placeholders like `{}` intact. These are used to inject dynamic data (e.g., port numbers).
    - Example: `PORT_SPECIFIC_OPEN=ALERT : ポート {} ({}) が開かれています！`
4.  **Run**: Execute with the new code: `sudo python3 LSA.py ja`
