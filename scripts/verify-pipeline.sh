#!/bin/bash

# =============================================================================
# Sentinel-AWS Cyber-Optimizer — Local Pipeline Simulator
# Mirrors the logic of .github/workflows/ci-cd-pipeline.yml
# =============================================================================

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Starting Local CI/CD Pipeline Simulation ===${NC}\n"

# Check dependencies
echo "🔍 Checking local environment..."
export PATH="$HOME/.local/bin:$PATH"

# Function to check tool availability
check_tool() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}⚠️  $1 not found. Skipping related steps.${NC}"
        return 1
    fi
    return 0
}

# Phase 1: Unit Tests & Security Linting
echo -e "\n${GREEN}[Step 1/4] Running Unit Tests & Security Lint (Bandit)${NC}"
if check_tool python3 && check_tool pytest; then
    cd lambda
    python3 -m pytest tests/ -v --tb=short --cov=log_transformer --cov-report=term-missing
    cd ..
else
    echo "Skipping Step 1 (python3/pytest missing)"
fi

if check_tool bandit; then
    echo "Running Bandit security lint..."
    bandit -r lambda/ -ll
fi

# Phase 2: IaC Compliance (Terraform + Checkov)
echo -e "\n${GREEN}[Step 2/4] Running IaC Validation & Compliance (Checkov)${NC}"
if check_tool terraform; then
    cd terraform
    terraform init -backend=false > /dev/null 2>&1
    terraform validate
    cd ..
fi

if check_tool checkov; then
    echo "Running Checkov compliance scan..."
    checkov -d terraform/ --config-file security/checkov-config.yml --compact --quiet
fi

# Phase 3: Container Build (Local check)
echo -e "\n${GREEN}[Step 3/4] Testing Docker Build (Hardened Image)${NC}"
if check_tool docker; then
    echo "Building simulation image..."
    docker build -t sentinel-optimizer:local -f docker/Dockerfile .
else
    echo "Skipping Step 3 (docker missing)"
fi

# Phase 4: Vulnerability & SBOM (Conditional on tools)
echo -e "\n${GREEN}[Step 4/4] Security Scanning (Trivy/Syft)${NC}"
if check_tool trivy; then
    echo "Running Trivy CVE scan..."
    trivy image --severity CRITICAL,HIGH --exit-code 0 sentinel-optimizer:local
else
    echo "Skipping Trivy scan (trivy missing)"
fi

if check_tool syft; then
    echo "Generating SBOM..."
    syft sentinel-optimizer:local --output cyclonedx-json=sbom.json
    echo "SBOM generated: sbom.json"
else
    echo "Skipping Syft SBOM (syft missing)"
fi

echo -e "\n${GREEN}=== Local Pipeline Verification Complete! ===${NC}"
echo "Jobs marked as PASSED mirror the logic that will run in GitHub Actions."
echo "Note: Terraform Plan/Apply and EKS Deploy require live AWS credentials."
