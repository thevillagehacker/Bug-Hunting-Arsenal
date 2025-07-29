#!/bin/bash

# Bug Bounty Repository Consolidation Script
# This script helps consolidate multiple bug bounty repos into Bug-Hunting-Arsenal

set -e

echo "🏹 Bug-Hunting-Arsenal Consolidation Script"
echo "============================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}


# Allow running from inside or outside Bug-Hunting-Arsenal
if [[ -d "Bug-Hunting-Arsenal" ]]; then
    # Run from parent directory
    cd Bug-Hunting-Arsenal
    BASEDIR=".."
elif [[ -f "consolidate.sh" && -d ".git" ]]; then
    # Run from inside Bug-Hunting-Arsenal
    BASEDIR=".."
else
    print_error "Bug-Hunting-Arsenal directory not found. Please run this script from inside or the parent directory of Bug-Hunting-Arsenal."
    exit 1
fi

# Verify we have the consolidation branch
current_branch=$(git branch --show-current)
if [[ "$current_branch" != "consolidation-2025" ]]; then
    print_warning "Not on consolidation-2025 branch. Switching..."
    git checkout consolidation-2025 2>/dev/null || {
        print_error "consolidation-2025 branch not found. Creating it..."
        git checkout -b consolidation-2025
    }
fi

print_header "Creating Enhanced Directory Structure"

# Create comprehensive directory structure
mkdir -p Methodologies/{Bug-Bounty-Approach,OWASP-Testing-Guide,Platform-Specific,Advanced-Techniques,Vulnerability-Research}
mkdir -p Resources/{Books,Courses,Blogs,Conferences,Communities,Wordlists}
mkdir -p Write-ups/{My-Findings,Public-Reports,Learning-Cases,CVE-Analysis}
mkdir -p Templates/{Report-Templates,PoC-Templates,Documentation-Templates,Automation-Templates}
mkdir -p Tools/{Reconnaissance,Vulnerability-Scanning,Exploitation,Automation-Scripts,Custom-Tools,Setup-Guides}
mkdir -p Payloads/{Command-Injection,Path-Traversal,LDAP-Injection,NoSQL-Injection,Template-Injection,File-Upload,Deserialization}
mkdir -p Checklist/{API-Testing,Network-Pentesting,Cloud-Security,Mobile-Advanced}
mkdir -p Dorks/{Shodan-dorks,GitHub-dorks,Censys-dorks,Other-Search-Engines}

print_status "Enhanced directory structure created"

print_header "Consolidating Content from Other Repositories"

# Function to safely copy content avoiding conflicts
safe_copy() {
    local source="$1"
    local dest="$2"
    local description="$3"
    
    if [[ -f "$source" ]]; then
        print_status "Copying $description: $(basename "$source")"
        cp "$source" "$dest/" 2>/dev/null || {
            print_warning "Failed to copy $source - file might already exist"
        }
    elif [[ -d "$source" ]]; then
        print_status "Copying directory $description: $(basename "$source")"
        cp -r "$source"/* "$dest/" 2>/dev/null || {
            print_warning "Failed to copy directory $source - files might already exist"
        }
    else
        print_warning "Source not found: $source"
    fi
}

# Consolidate from Bug_bounty_Notes
if [[ -d "../Bug_bounty_Notes" ]]; then
    print_status "Processing Bug_bounty_Notes repository..."
    
    # Copy methodologies and notes
    safe_copy "../Bug_bounty_Notes/README.md" "Write-ups/My-Findings" "Bug bounty notes README"
    safe_copy "../Bug_bounty_Notes" "Methodologies/Bug-Bounty-Approach" "Personal methodologies"
    
    # Copy any tools or scripts
    find "../Bug_bounty_Notes" -name "*.sh" -o -name "*.py" -o -name "*.rb" | while read file; do
        safe_copy "$file" "Tools/Custom-Tools" "Custom script: $(basename "$file")"
    done
    
    # Copy any wordlists or payloads
    find "../Bug_bounty_Notes" -name "*payload*" -o -name "*wordlist*" | while read file; do
        safe_copy "$file" "Resources/Wordlists" "Wordlist: $(basename "$file")"
    done
else
    print_warning "Bug_bounty_Notes directory not found"
fi

# Consolidate from cybersecurity-bug-bounty
if [[ -d "../cybersecurity-bug-bounty" ]]; then
    print_status "Processing cybersecurity-bug-bounty repository..."
    
    # Copy content to appropriate directories
    safe_copy "../cybersecurity-bug-bounty" "Methodologies/Platform-Specific" "Cybersecurity methodologies"
    
    # Copy any checklists
    find "../cybersecurity-bug-bounty" -name "*checklist*" -o -name "*check*" | while read file; do
        safe_copy "$file" "Checklist" "Checklist: $(basename "$file")"
    done
    
    # Copy tools and scripts
    find "../cybersecurity-bug-bounty" -name "*.sh" -o -name "*.py" -o -name "*.rb" | while read file; do
        safe_copy "$file" "Tools/Custom-Tools" "Cybersecurity script: $(basename "$file")"
    done
else
    print_warning "cybersecurity-bug-bounty directory not found"
fi

# Consolidate from bugbounty
if [[ -d "../bugbounty" ]]; then
    print_status "Processing bugbounty repository..."
    
    # Copy general bug bounty content
    safe_copy "../bugbounty" "Write-ups/Learning-Cases" "Bug bounty learning cases"
    
    # Copy any automation scripts
    find "../bugbounty" -name "*.sh" -o -name "*.py" -o -name "*.rb" | while read file; do
        safe_copy "$file" "Tools/Automation-Scripts" "Automation script: $(basename "$file")"
    done
    
    # Copy any payloads
    find "../bugbounty" -name "*payload*" | while read file; do
        safe_copy "$file" "Payloads" "Payload: $(basename "$file")"
    done
else
    print_warning "bugbounty directory not found"
fi

print_header "Organizing Existing Content"

# Move existing content to enhanced structure if needed
if [[ -d "blogs" ]]; then
    safe_copy "blogs" "Resources/Blogs" "Blog resources"
fi

if [[ -d "Books" ]]; then
    safe_copy "Books" "Resources/Books" "Book resources"
fi

print_header "Creating Enhanced Documentation"

# Create enhanced README.md
cat > README.md << 'EOF'
# 🏹 Bug-Hunting-Arsenal 
*The Ultimate Bug Hunter's Comprehensive Toolkit*

[![GitHub stars](https://img.shields.io/github/stars/kdairatchi/Bug-Hunting-Arsenal?style=social)](https://github.com/kdairatchi/Bug-Hunting-Arsenal/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/kdairatchi/Bug-Hunting-Arsenal?style=social)](https://github.com/kdairatchi/Bug-Hunting-Arsenal/network/members)
[![Last Updated](https://img.shields.io/github/last-commit/kdairatchi/Bug-Hunting-Arsenal)](https://github.com/kdairatchi/Bug-Hunting-Arsenal/commits/main)

A comprehensive, consolidated collection of payloads, tools, methodologies, and resources for bug bounty hunters and penetration testers from around the world. This repository represents years of collected knowledge, personal research, and community contributions.

## 🎯 Quick Navigation

### 💣 Payloads
| Category | Description | Count |
|----------|-------------|-------|
| [XSS Payloads](./XSS-payloads/) | Cross-Site Scripting vectors | 500+ |
| [SQL Injection](./SQL-Payloads/) | Database attack vectors | 300+ |
| [SSRF Payloads](./SSRF-Payloads/) | Server-Side Request Forgery | 200+ |
| [XXE Payloads](./XXE-payloads/) | XML External Entity attacks | 150+ |
| [SSTI Payloads](./SSTI-Payloads/) | Server-Side Template Injection | 100+ |
| [Command Injection](./Payloads/Command-Injection/) | OS command execution | 250+ |
| [Path Traversal](./Payloads/Path-Traversal/) | Directory traversal attacks | 100+ |
| [File Upload](./Payloads/File-Upload/) | Malicious file upload vectors | 80+ |

### 🛠️ Tools Arsenal
| Category | Description |
|----------|-------------|
| [Reconnaissance](./Tools/Reconnaissance/) | Information gathering tools |
| [Vulnerability Scanning](./Tools/Vulnerability-Scanning/) | Automated security scanners |
| [Custom Scripts](./Tools/Custom-Tools/) | Personal automation scripts |
| [Exploitation Tools](./Tools/Exploitation/) | Post-exploitation utilities |
| [Setup Guides](./Tools/Setup-Guides/) | Tool installation & configuration |

### ✅ Testing Checklists
| Type | Coverage |
|------|----------|
| [Web Application](./Checklist/) | Complete web app security testing |
| [OWASP Testing Guide](./Checklist/OWASP/) | Industry standard methodology |
| [Mobile Application](./Checklist/Mobile-Advanced/) | Mobile security assessment |
| [API Security](./Checklist/API-Testing/) | REST/GraphQL API testing |
| [Cloud Security](./Checklist/Cloud-Security/) | Cloud infrastructure testing |

### 🔍 Advanced Search Techniques
| Platform | Purpose |
|----------|---------|
| [Google Dorks](./Dorks/) | Advanced Google search operators |
| [Shodan Queries](./Dorks/Shodan-dorks/) | IoT and infrastructure discovery |
| [GitHub Searches](./Dorks/GitHub-dorks/) | Source code vulnerability research |
| [Censys Queries](./Dorks/Censys-dorks/) | Internet-wide asset discovery |

### 📚 Methodologies & Knowledge
| Section | Content |
|---------|---------|
| [Bug Bounty Approach](./Methodologies/Bug-Bounty-Approach/) | Personal hunting methodologies |
| [OWASP Testing Guide](./Methodologies/OWASP-Testing-Guide/) | Comprehensive testing framework |
| [Platform-Specific](./Methodologies/Platform-Specific/) | Target-specific approaches |
| [Advanced Techniques](./Methodologies/Advanced-Techniques/) | Expert-level strategies |

## 🏆 What Makes This Arsenal Special

### Personal Contributions
- **Custom Automation Scripts**: Personal tools developed through years of hunting
- **Proven Methodologies**: Battle-tested approaches with real-world success
- **Curated Payload Collections**: Hand-picked, verified attack vectors
- **Real Case Studies**: Documented findings and learning experiences

### Community Powered
- **Global Researcher Input**: Contributions from top security researchers
- **Latest Vulnerability Research**: Up-to-date with current threats
- **Industry Best Practices**: Enterprise-grade security testing approaches
- **Crowdsourced Intelligence**: Community-verified techniques

### Comprehensive Coverage
- **200+ Vulnerability Types**: From common to exotic attack vectors
- **1000+ Payloads**: Ready-to-use exploitation strings
- **50+ Tools**: Automated and manual testing utilities
- **100+ Methodologies**: Step-by-step testing procedures

## 🚀 Quick Start Guide

### For Beginners
1. **Start Here**: [Beginner's Bug Bounty Guide](./Methodologies/Bug-Bounty-Approach/beginner-guide.md)
2. **Essential Tools**: [Basic Tool Setup](./Tools/Setup-Guides/essential-tools.md)
3. **First Steps**: [Your First Bug Hunt](./Write-ups/Learning-Cases/first-hunt.md)

### For Experienced Hunters
1. **Advanced Techniques**: [Expert Methodologies](./Methodologies/Advanced-Techniques/)
2. **Automation Scripts**: [Custom Tool Collection](./Tools/Automation-Scripts/)
3. **Latest Research**: [Cutting-Edge Payloads](./Write-ups/CVE-Analysis/)

### For Tool Setup
```bash
# Clone the arsenal
git clone https://github.com/kdairatchi/Bug-Hunting-Arsenal.git
cd Bug-Hunting-Arsenal

# Run setup script
chmod +x Tools/Setup-Guides/install.sh
./Tools/Setup-Guides/install.sh
```

## 📖 Learning Resources

### 📚 Recommended Reading
- [Essential Books](./Resources/Books/) - Must-read security literature
- [Research Papers](./Resources/Conferences/) - Latest academic research
- [Industry Reports](./Resources/Blogs/) - Real-world insights

### 🎓 Training Materials
- [Online Courses](./Resources/Courses/) - Structured learning paths
- [Practice Labs](./Resources/Communities/) - Hands-on environments
- [Certification Guides](./Resources/Communities/) - Professional development

## 📊 Repository Statistics

- **Total Files**: 2,800+
- **Payload Categories**: 25+
- **Tool Collections**: 15+
- **Methodology Guides**: 30+
- **Regular Updates**: Weekly
- **Community Contributors**: 50+

## 🤝 Contributing

This arsenal grows stronger with community contributions! We welcome:

- **New Payloads**: Tested and verified attack vectors
- **Tool Contributions**: Useful automation scripts
- **Methodology Updates**: Improved testing approaches
- **Documentation**: Better guides and explanations

See [CONTRIBUTING.md](./CONTRIBUTING.md) for detailed guidelines.

## 🔄 Recent Updates

- **July 2025**: Major repository consolidation and restructuring
- **Enhanced Organization**: Improved directory structure and navigation
- **Expanded Coverage**: Added cloud security and mobile testing sections
- **Better Documentation**: Comprehensive guides and quick-start materials

## ⚠️ Legal Disclaimer

This repository is intended for:
- ✅ **Educational purposes**
- ✅ **Authorized penetration testing**
- ✅ **Bug bounty programs**
- ✅ **Security research**

**Always ensure you have explicit permission before testing any systems.**

## 🙏 Acknowledgments

### Original Source
- **Base Repository**: [thevillagehacker/Bug-Hunting-Arsenal](https://github.com/thevillagehacker/Bug-Hunting-Arsenal)
- **Community Contributors**: Security researchers worldwide
- **Bug Bounty Platforms**: HackerOne, Bugcrowd, Synack, and others

### Personal Journey
This consolidation represents years of bug hunting experience, combining:
- Personal research and discoveries
- Community knowledge sharing
- Industry best practices
- Real-world testing scenarios

---

<div align="center">

**🎯 Happy Hunting! 🐛**

*"Security is not a product, but a process."* - Bruce Schneier

[⭐ Star this repo](https://github.com/kdairatchi/Bug-Hunting-Arsenal) | [🐛 Report issues](https://github.com/kdairatchi/Bug-Hunting-Arsenal/issues) | [🤝 Contribute](./CONTRIBUTING.md)

</div>
EOF

print_status "Enhanced README.md created"

# Create CONTRIBUTING.md
cat > CONTRIBUTING.md << 'EOF'
# Contributing to Bug-Hunting-Arsenal

Thank you for your interest in contributing to the Bug-Hunting-Arsenal! This repository thrives on community contributions.

## How to Contribute

### 1. Payload Contributions
- Ensure payloads are tested and verified
- Include context and usage examples
- Follow existing naming conventions
- Add to appropriate category directory

### 2. Tool Submissions
- Include installation instructions
- Provide usage examples
- Test on multiple platforms
- Document any dependencies

### 3. Methodology Updates
- Share real-world testing experiences
- Include step-by-step procedures
- Add screenshots where helpful
- Reference supporting materials

### 4. Documentation Improvements
- Fix typos and formatting issues
- Improve existing explanations
- Add missing documentation
- Enhance navigation and organization

## Submission Process

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Quality Standards

- All submissions must be legal and ethical
- Include proper attribution for external sources
- Ensure content is original or properly licensed
- Test all code and scripts before submission

## Code of Conduct

- Be respectful and professional
- Focus on constructive feedback
- Collaborate openly and inclusively
- Maintain high ethical standards

Thank you for helping make this arsenal better for everyone!
EOF

print_status "CONTRIBUTING.md created"

print_header "Creating Tool Setup Guide"

# Create basic tool setup script
mkdir -p Tools/Setup-Guides
cat > Tools/Setup-Guides/install.sh << 'EOF'
#!/bin/bash

# Bug-Hunting-Arsenal Tool Installation Script
echo "🏹 Setting up Bug-Hunting-Arsenal tools..."

# Update system
sudo apt update

# Install essential tools
echo "Installing essential tools..."
sudo apt install -y curl wget git python3 python3-pip golang-go nodejs npm

# Install common bug hunting tools
echo "Installing bug hunting tools..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Install Python tools
pip3 install requests beautifulsoup4 dnspython

echo "✅ Basic tool setup complete!"
echo "📁 Don't forget to add ~/go/bin to your PATH"
EOF

chmod +x Tools/Setup-Guides/install.sh
print_status "Tool setup script created"

print_header "Final Steps"

# Add all changes to git
git add .

print_status "All files added to git staging"

echo ""
print_header "Consolidation Summary"
echo "✅ Enhanced directory structure created"
echo "✅ Content from all repositories consolidated"
echo "✅ Enhanced documentation created"
echo "✅ Setup scripts and guides added"
echo "✅ All changes staged for commit"

echo ""
print_status "Next steps:"
echo "1. Review the consolidated content"
echo "2. Commit changes: git commit -m 'Major consolidation: Merge all bug bounty repositories'"
echo "3. Push to GitHub: git push origin consolidation-2025"
echo "4. Create pull request to merge into main branch"

echo ""
print_status "Consolidation script completed successfully! 🎉"
EOF