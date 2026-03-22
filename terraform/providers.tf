# =============================================================================
# Sentinel-AWS Cyber-Optimizer — Provider Configuration
# Multi-account simulation using provider aliases
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

# -----------------------------------------------------------------------------
# Security Account Provider (centralized security services)
# -----------------------------------------------------------------------------
provider "aws" {
  alias  = "security"
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      Account     = "security"
      ManagedBy   = "terraform"
    }
  }
}

# -----------------------------------------------------------------------------
# Client Account Provider (workload resources)
# -----------------------------------------------------------------------------
provider "aws" {
  alias  = "client"
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      Account     = "client"
      ManagedBy   = "terraform"
    }
  }
}

# -----------------------------------------------------------------------------
# Default Provider (used by modules that don't require explicit account context)
# -----------------------------------------------------------------------------
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# -----------------------------------------------------------------------------
# Kubernetes Provider (configured after EKS creation)
# -----------------------------------------------------------------------------
provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_ca_certificate)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}
