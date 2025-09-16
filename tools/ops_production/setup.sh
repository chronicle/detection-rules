#!/bin/bash

# Chronicle Production Manager Setup Script
# Engineering Officer's Implementation for Captain Picard

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                  Chronicle Production Manager Setup                           ║${NC}"
echo -e "${BLUE}║                Engineering Officer's Implementation                           ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════════════════════╝${NC}"
echo

# Check if we're in the right directory
if [[ ! -f "bulk_detection_manager.py" ]]; then
    echo -e "${RED}Error: Must run setup from tools/ops_production directory${NC}"
    exit 1
fi

echo -e "${BLUE}[1/4] Setting up Python virtual environment...${NC}"
if [[ ! -d "venv" ]]; then
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${YELLOW}! Virtual environment already exists${NC}"
fi

echo -e "${BLUE}[2/4] Installing Python dependencies...${NC}"
source venv/bin/activate
pip install -r requirements.txt > /dev/null 2>&1
echo -e "${GREEN}✓ Dependencies installed${NC}"

echo -e "${BLUE}[3/4] Validating configuration...${NC}"
if [[ -f "config.yaml" ]]; then
    echo -e "${GREEN}✓ Configuration file found${NC}"
else
    echo -e "${RED}✗ Configuration file missing${NC}"
    exit 1
fi

# Check service account file
SA_FILE=$(python3 -c "import yaml; print(yaml.safe_load(open('config.yaml'))['chronicle']['service_account_file'])" 2>/dev/null || echo "")
if [[ -n "$SA_FILE" && -f "$SA_FILE" ]]; then
    echo -e "${GREEN}✓ Service account key found${NC}"
else
    echo -e "${YELLOW}! Service account key not found: $SA_FILE${NC}"
    echo -e "${YELLOW}  This is expected if credentials are managed differently${NC}"
fi

echo -e "${BLUE}[4/4] Testing system status...${NC}"
./chronicle_manager.sh status

echo
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                            Setup Complete!                                   ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "${BLUE}Next steps:${NC}"
echo -e "  1. Test authentication: ${YELLOW}./chronicle_manager.sh auth test${NC}"
echo -e "  2. Validate rules: ${YELLOW}./chronicle_manager.sh rules verify-all${NC}"
echo -e "  3. Generate report: ${YELLOW}./chronicle_manager.sh report generate${NC}"
echo
echo -e "${BLUE}Remember to activate the virtual environment before running tools:${NC}"
echo -e "  ${YELLOW}source venv/bin/activate${NC}"
echo

