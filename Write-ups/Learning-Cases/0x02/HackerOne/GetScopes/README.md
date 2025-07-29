# GetScopes - HackerOne Scope Collector

A command-line tool designed to automatically collect all in-scope targets from HackerOne bug bounty programs. The tool fetches each program's scope information, including domains and wildcards, making it easier for bug bounty hunters to gather and organize target information.

## Key Features

- **Automated Scope Collection**: Automatically fetches scope information from every HackerOne program
- **Smart Filtering**:
  - Separates direct domains (e.g., example.com) from wildcards (e.g., *.example.com)
  - Only collects eligible/active scope targets
  - Can filter between bounty and VDP programs
- **Rate Limited**: Built-in protection against API rate limits (600 requests/minute)
- **Flexible Output**:
  - Text format: Clean list of domains and wildcards
  - JSON format: Detailed information including scope instructions and eligibility status

## What Does It Do?

1. Fetches list of all available HackerOne programs
2. For each program:
   - Gets structured scope information
   - Extracts domains and wildcards
   - Verifies if targets are eligible for testing
3. Organizes collected targets by:
   - Regular domains (e.g., api.example.com)
   - Wildcard domains (e.g., *.example.com)
4. Saves results in either plain text or detailed JSON format

## Quick Start

```bash
git clone https://github.com/alpernae/bugbounty.git
cd bugbounty/GetScopes
pip install -r requirements.txt
chmod +x getallscope.py
```

## Configuration

```bash
./getallscope.py -c "username:api_token"
```
Credentials are securely stored in `~/.config/getscope/config.yaml`

## Usage Examples

### Get All Targets

```bash
# Fetch everything
./getallscope.py

# Get only bounty program targets
./getallscope.py -b true

# Get only VDP targets
./getallscope.py -b false
```

### Save Results

```bash
# Save as simple text list
./getallscope.py -o txt

# Save as detailed JSON
./getallscope.py -o json
```

### Filter Results

```bash
# Extract wildcards
./filter.py -w scope_all_programs.txt -f w

# Extract domains
./filter.py -w scope_all_programs.txt -f d
```

## Output Formats

### Text Output (Default)

Simple list of domains and wildcards:
```
domain1.com
domain2.com
*.wildcard1.com
```

### JSON Output (Detailed)

Structured data with metadata:
```json
{
  "programs": {
    "program1": {
      "urls": [
        {
          "domain": "domain1.com",
          "instruction": "Test on production",
          "eligible": true
        }
      ],
      "wildcards": [
        {
          "domain": "*.program1.com",
          "instruction": "No load testing",
          "eligible": true
        }
      ]
    }
  },
  "metadata": {
    "total_programs": 562,
    "program_type": "bounty"
  }
}
```

## Rate Limiting

- Maximum 600 requests per minute
- Automatic backoff on API limits
- Smart request queuing
- Safe for continuous use

## Author

- [@alpernae](https://github.com/alpernae)

## License

MIT
