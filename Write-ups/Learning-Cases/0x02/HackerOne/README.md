# HACKERONE

The `hackerone/` folder contains tools specifically designed to interact with the HackerOne platform, aiding bug bounty hunters in automating and simplifying tasks associated with managing HackerOne programs and submissions.

<details>
<summary> <strong>0x01 | h1fecther</strong></summary>

#### Description:
`h1fetcher.sh` is a Bash script designed to query a specific HackerOne program for in-scope or out-of-scope targets based on their eligibility for submission. The script retrieves data from the HackerOne API and allows users to filter results based on scope (eligible for submission or not). The filtered results are saved to an output file.

</details>

<details>
<summary> <strong>0x02 | GetScopes</strong></summary>

#### Description:
A command-line tool designed to automatically collect all in-scope targets from HackerOne bug bounty programs. The tool fetches each program's scope information, including domains and wildcards, making it easier for bug bounty hunters to gather and organize target information.

</details>

#### Key Tools:

- **h1fetcher.sh**: 
  A script to fetch structured scopes and program details from HackerOne based on the provided handle. It helps to quickly retrieve eligible in-scope targets for a particular program.
  
- **h1reporter.sh** (Future Script): 
  Planned to automate the reporting process for HackerOne submissions, streamlining the process of crafting and submitting bug reports with proper formatting.
  
- **h1alerts.sh** (Future Script): 
  A script under development that will notify users of any changes or updates in the scope or bounty programs they are monitoring, helping hunters stay informed.
  Each script is designed to interact directly with the HackerOne API, leveraging API credentials for seamless integration and efficiency in bug bounty workflows. The folder is intended to grow with more HackerOne-specific utilities to support various bug bounty processes.
