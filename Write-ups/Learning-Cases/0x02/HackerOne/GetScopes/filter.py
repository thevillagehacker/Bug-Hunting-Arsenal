import re
import json
import argparse


def filter_lines(lines, filter_type):
    # Regex patterns
    wildcard_pattern = re.compile(r"^\*\.[a-zA-Z0-9-]+\.[a-zA-Z]+$")
    domain_pattern = re.compile(r"^[a-zA-Z0-9-]+\.[a-zA-Z]+$")
    
    filtered = []
    for line in lines:
        # Remove paths like /xyz or /*
        clean_line = re.sub(r"/.*", "", line.strip())
        
        if filter_type == "w" and wildcard_pattern.match(clean_line):
            filtered.append(clean_line)
        elif filter_type == "d" and domain_pattern.match(clean_line):
            filtered.append(clean_line)
    
    return filtered


def process_file(input_file, filter_type):
    # Load data based on file extension
    if input_file.endswith(".json"):
        with open(input_file, "r") as file:
            data = json.load(file)
        # Flatten JSON if it contains lists or nested elements
        if isinstance(data, list):
            lines = [str(item) for item in data]
        elif isinstance(data, dict):
            lines = [str(value) for value in data.values()]
        else:
            raise ValueError("Invalid JSON structure.")
    elif input_file.endswith(".txt"):
        with open(input_file, "r") as file:
            lines = file.readlines()
    else:
        raise ValueError("Unsupported file format. Use .txt or .json.")
    
    # Filter lines based on the specified type
    return filter_lines(lines, filter_type)


def main():
    parser = argparse.ArgumentParser(description="Filter wildcards and domains from a file.")
    parser.add_argument("-w", "--file", required=True, help="Input file (txt or json).")
    parser.add_argument("-f", "--filter", required=True, choices=["w", "d"],
                        help="Filter type: 'w' for wildcards, 'd' for domains.")
    args = parser.parse_args()

    try:
        # Process file and get filtered output
        filtered_output = process_file(args.file, args.filter)
        
        # Determine output file name
        output_file = "wildcards.txt" if args.filter == "w" else "domains.txt"
        
        # Save the filtered output to a file
        with open(output_file, "w") as file:
            file.write("\n".join(filtered_output))
        
        print(f"Filtered data saved to '{output_file}'.")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
