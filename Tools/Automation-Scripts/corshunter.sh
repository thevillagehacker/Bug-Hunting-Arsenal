#!/bin/bash
# Author: Alperen ERGEL

# Banner


cat << "EOF"
   ______                __  __            __           
  / ____/___  __________/ / / /_  ______  / /____  _____
 / /   / __ \/ ___/ ___/ /_/ / / / / __ \/ __/ _ \/ ___/
/ /___/ /_/ / /  (__  ) __  / /_/ / / / / /_/  __/ /    
\____/\____/_/  /____/_/ /_/\__,_/_/ /_/\__/\___/_/     
                                                       
EOF

# Function to display usage
usage() {
    echo "Usage: $0 -u single_domain.com | -i list_of_urls.txt [-o output_file] [-v]"
    echo "  -u   Single domain to check"
    echo "  -i   File with a list of URLs to check (one per line)"
    echo "  -o   Optional output file to save results"
    echo "  -v   Verbose mode for detailed output"
    exit 1
}

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Parse command-line arguments
VERBOSE=false
while getopts "u:i:o:v" opt; do
    case ${opt} in
        u )
            DOMAIN=$OPTARG
            ;;
        i )
            URL_FILE=$OPTARG
            ;;
        o )
            OUTPUT_FILE=$OPTARG
            ;;
        v )
            VERBOSE=true
            ;;
        \? )
            usage
            ;;
    esac
done
shift $((OPTIND -1))

# Ensure either -u or -i is specified
if [ -z "${DOMAIN}" ] && [ -z "${URL_FILE}" ];then
    echo -e "${RED}Error: Either -u or -i must be specified.${NC}"
    usage
fi

# Check for conflicting -u and -i
if [ -n "${DOMAIN}" ] && [ -n "${URL_FILE}" ];then
    echo -e "${RED}Error: Cannot specify both -u and -i.${NC}"
    usage
fi

# Function to add https:// if no scheme is provided
add_scheme() {
    local url=$1
    if [[ ! $url =~ ^http:// ]] && [[ ! $url =~ ^https:// ]];then
        echo "https://${url}"
    else
        echo "${url}"
    fi
}

# Function to check reflected CORS
reflected_cors() {
    local url=$1
    local method=$2
    local evil_origin="https://evil.${url}"
    echo -e "${GREEN}[*] Testing reflected for CORS origin with method: ${method}${NC}"
    local response=$(curl -s --max-time 15 -X "$method" -I -H "Origin: ${evil_origin}" "${url}")
    
    if [ "$VERBOSE" = true ];then
        echo "${method} Response Headers:"
        echo "$response"
    fi

    if echo "$response" | grep -iq "Access-Control-Allow-Origin: ${evil_origin}" && \
       echo "$response" | grep -iq "Access-Control-Allow-Credentials: true";then
        echo -e "${YELLOW}[!] Found reflected CORS origin: ${evil_origin} with ${method}${NC}"
        echo "${url} - Reflected CORS - Method: ${method}" >> "${OUTPUT_FILE}"
        return 0  # Vulnerable
    else
        echo -e "${YELLOW}[*] No reflected CORS origin found with ${method}.${NC}"
        return 1  # Not vulnerable
    fi
}

# Function to check wildcard CORS
wildcard_cors() {
    local url=$1
    echo -e "${GREEN}[*] Testing wildcard CORS origins${NC}"
    local response=$(curl -s --max-time 15 -X GET -I -H "Origin: https://evil.${url}" "${url}")
    
    if [ "$VERBOSE" = true ];then
        echo "Wildcard Response Headers:"
        echo "$response"
    fi

    if echo "$response" | grep -iq "Access-Control-Allow-Origin: *";then
        echo -e "${YELLOW}[!] Found wildcard CORS origin: *${NC}"
        return 0  # Vulnerable
    else
        echo -e "${YELLOW}[*] No wildcard CORS origin found.${NC}"
        return 1  # Not vulnerable
    fi
}

# Function to check pre-domain CORS
pre_domain_cors() {
    local url=$1
    local evil_origin="https://evil.${url#*://}"
    echo -e "${GREEN}[*] Testing pre-domain CORS origin: ${evil_origin}${NC}"
    local response=$(curl -s --max-time 15 -X OPTIONS -I -H "Origin: ${evil_origin}" "${url}")

    if [ "$VERBOSE" = true ];then
        echo "OPTIONS Request Headers:"
        echo "$response"
    fi

    if echo "$response" | grep -iq "Access-Control-Allow-Origin: ${evil_origin}" && \
       echo "$response" | grep -iq "Access-Control-Allow-Credentials: true";then
        echo -e "${YELLOW}[!] Found CORS origin in pre-domain check: ${evil_origin}${NC}"
        echo "${url} - Pre-domain CORS" >> "${OUTPUT_FILE}"
        return 0  # Vulnerable
    else
        echo -e "${YELLOW}[*] No CORS origin found in pre-domain check.${NC}"
        return 1  # Not vulnerable
    fi
}

# Function to check a single URL with multiple methods and wildcard origins
check_url() {
    local url=$(add_scheme "$1")
    local methods=("GET" "POST" "PUT" "DELETE" "PATCH")
    local cors_vuln=false
    local pre_flight_vuln=false
    local wildcard_vuln=false
    local vulnerable_methods=()

    echo -e "${GREEN}[*] Checking URL: ${url}${NC}"
    
    for method in "${methods[@]}";do
        reflected_cors "$url" "$method"
        if [ $? -eq 0 ];then
            cors_vuln=true
            vulnerable_methods+=("${method}")
        fi

        # Pre-domain check
        pre_domain_cors "$url"
        if [ $? -eq 0 ];then
            pre_flight_vuln=true
            break # Stop further checks if pre-domain is vulnerable
        fi
    done

    # Check for wildcard CORS
    wildcard_cors "$url"
    if [ $? -eq 0 ];then
        wildcard_vuln=true
    fi

    # Determine result
    if [ "$cors_vuln" = true ] || [ "$pre_flight_vuln" = true ] || [ "$wildcard_vuln" = true ];then
        echo -e "${RED}[!] URL: ${url} - Vulnerable to CORS.${NC}"
        if [ ${#vulnerable_methods[@]} -gt 0 ];then
            echo -e "${RED}[!] Vulnerable methods: ${vulnerable_methods[*]}${NC}"
        fi
    else
        echo -e "${GREEN}[*] URL: ${url} is not Vulnerable to CORS.${NC}"
    fi
}

# Check single domain
if [ -n "${DOMAIN}" ];then
    domain_with_scheme=$(add_scheme "${DOMAIN}")
    check_url "${domain_with_scheme}"
fi

# Check list of URLs
if [ -n "${URL_FILE}" ];then
    while IFS= read -r url;do
        url_with_scheme=$(add_scheme "${url}")
        check_url "${url_with_scheme}"
    done < "${URL_FILE}"
fi
