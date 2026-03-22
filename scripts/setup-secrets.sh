#!/bin/bash

# =============================================================================
# Sentinel-AWS Cyber-Optimizer — GitHub Secrets Bootstrapper
# Automates the setup of required CI/CD security secrets.
# =============================================================================

set -e

# Colors for output
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== GitHub Secrets Automation Script ===${NC}\n"

# 1. Verification: Check for gh CLI
if ! command -v gh &> /dev/null; then
    echo -e "${RED}❌ Error: 'gh' CLI not found. Please install it first.${NC}"
    echo "Visit: https://cli.github.com/"
    exit 1
fi

# 2. Verification: Check for login
if ! gh auth status &> /dev/null; then
    echo -e "${YELLOW}⚠️  Not logged in to GitHub. Running 'gh auth login'...${NC}"
    gh auth login
fi

# 3. Collect Secret Values
echo -e "${CYAN}Please enter the required secret values (leave blank to skip):${NC}"

read -p "Enter AWS_ROLE_ARN (OIDC Role): " AWS_ROLE_ARN
read -p "Enter SBOM_BUCKET (S3 Bucket Name): " SBOM_BUCKET

# 4. Set Secrets
if [ -n "$AWS_ROLE_ARN" ]; then
    echo -e "\n${CYAN}Setting AWS_ROLE_ARN...${NC}"
    gh secret set AWS_ROLE_ARN --body "$AWS_ROLE_ARN"
    echo -e "${GREEN}✅ AWS_ROLE_ARN set successfully.${NC}"
fi

if [ -n "$SBOM_BUCKET" ]; then
    echo -e "\n${CYAN}Setting SBOM_BUCKET...${NC}"
    gh secret set SBOM_BUCKET --body "$SBOM_BUCKET"
    echo -e "${GREEN}✅ SBOM_BUCKET set successfully.${NC}"
fi

echo -e "\n${GREEN}=== Secrets Setup Complete! ===${NC}"
echo -e "You can verify them at: ${YELLOW}$(gh repo view --json url -q .url)/settings/secrets/actions${NC}"
