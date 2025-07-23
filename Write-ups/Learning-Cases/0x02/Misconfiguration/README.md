# MISCONFIGURATION

The `misconfiguration/` folder contains tools and scripts focused on identifying and exploiting common web application misconfigurations. These tools assist bug bounty hunters in automating checks for weak or incorrect configurations in web servers, applications, and security settings.

<details>
<summary> <strong>0x01 | corshunter</strong></summary>

#### Description:
`corshunter.sh` is a Bash script that checks for **Cross-Origin Resource Sharing (CORS)** misconfigurations, specifically targeting **reflected CORS**, **wildcard CORS**, and **pre-domain CORS** issues. The script allows users to check single domains or lists of URLs and identifies vulnerable CORS configurations.

#### Features:
- **Command-line Arguments**:
  - `-u`: Single domain to check.
  - `-i`: File containing a list of URLs to check (one per line).
  - `-o` (optional): Output file to save vulnerable targets.
  - `-v` (optional): Verbose mode for detailed output.

- **CORS Vulnerability Checks**:
  - **Reflected CORS**: Detects if the origin in the request is reflected in the response headers.
  - **Wildcard CORS**: Tests if the application allows any origin (`*`) to access resources.
  - **Pre-domain CORS**: Checks for vulnerabilities by manipulating subdomains.

#### Usage:
```bash
./corshunter.sh -u example.com [-o output_file] [-v]
./corshunter.sh -i urls.txt [-o output_file] [-v]
```

#### Example:
```bash
./corshunter.sh -u example.com -v
```

This command tests `example.com` for CORS vulnerabilities with detailed output enabled.

#### Requirements:
- **Dependencies**:
  - `curl`: To send HTTP requests and gather headers.
  - Optional: Install `jq` for better response parsing (if needed).

#### Error Handling:
- If neither `-u` nor `-i` are provided, the script will exit with an error.
- If both `-u` and `-i` are provided together, the script will also exit with an error message.
- If no vulnerabilities are found, the script will notify the user and exit without writing data.

#### Installation:
1. Clone or download the script.
2. Make sure the script has executable permissions:
   ```bash
   chmod +x corshunter.sh
   ```

3. Run the script with the appropriate parameters.

</details>

#### Key Tools:

- **corshunter.sh**:
  A script designed to check for CORS misconfigurations in web applications, helping identify potential security risks in cross-origin resource sharing policies.

- **s3_bucket_checker.sh** (Future Script):
  Planned to detect misconfigured **S3 buckets** that allow public access, enabling the enumeration and exploitation of exposed resources.

- **misconfig_alerts.sh** (Future Script):
  A script under development that will notify users of any detected misconfigurations in their monitored targets, ensuring hunters stay informed of any security weaknesses.

Each script in the `misconfiguration/` folder focuses on automating the discovery of misconfigurations in web applications, streamlining the vulnerability detection process. The folder will be continuously updated with new tools to cover a wider range of misconfiguration checks.


This structure provides detailed descriptions and usage instructions for each tool, while also giving room for future additions and scripts.
