#!/bin/bash
# Author: Alperen ERGEL ()
# Banner


cat << "EOF"
    __   _______     __       __             
   / /_ <  / __/__  / /______/ /_  ___  _____
  / __ \/ / /_/ _ \/ __/ ___/ __ \/ _ \/ ___/
 / / / / / __/  __/ /_/ /__/ / / /  __/ /    
/_/ /_/_/_/  \___/\__/\___/_/ /_/\___/_/      
                                                       
EOF

# Initialize variables
handle=""
scope=""
output="targets.txt"

# Parse command-line arguments
while [[ "$#" -gt 0 ]]; do
  case $1 in
    -handle) handle="$2"; shift ;;
    -scope) scope="$2"; shift ;;
    -output) output="$2"; shift ;;
    *) echo "Invalid option: $1" 1>&2; exit 1 ;;
  esac
  shift
done

# Check if handle is provided
if [ -z "$handle" ]; then
  echo "Usage: $0 -handle [handle] -scope [true|false] [-output [file]]"
  exit 1
fi

# Check if scope is provided and valid
if [ "$scope" != "true" ] && [ "$scope" != "false" ]; then
  echo "Invalid scope value. Please provide 'true' or 'false'."
  exit 1
fi

# Check env variables
if [ -z "$H1_USERNAME" ] || [ -z "$H1_APIKEY" ]; then
  echo "API credentials not found in environment variables."
  exit 1
fi

# API call and results
curl -s -u "${H1_USERNAME}:${H1_APIKEY}" -H 'Accept: application/json' "https://api.hackerone.com/v1/hackers/programs/${handle}/structured_scopes?page%5Bsize%5D=100" |
jq --argjson scope "$([ "$scope" == "true" ] && echo true || echo false)" '.data[] | select(.attributes.eligible_for_submission == $scope) | .attributes.asset_identifier' | sed 's/"//g' > "$output"

# Print results
if [ ! -s "$output" ]; then
  echo "Found nothing to write!"
  exit 1
fi
