# =============================================================================
# Sentinel-AWS Cyber-Optimizer — Root Module Orchestration
# Multi-tenant cloud security infrastructure
# =============================================================================

locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# -----------------------------------------------------------------------------
# Phase 1: Networking — VPC, Subnets, NAT, Flow Logs
# -----------------------------------------------------------------------------
module "networking" {
  source = "./modules/networking"

  project_name         = var.project_name
  environment          = var.environment
  vpc_cidr             = var.vpc_cidr
  public_subnet_cidrs  = var.public_subnet_cidrs
  private_subnet_cidrs = var.private_subnet_cidrs
  availability_zones   = var.availability_zones
  cluster_name         = var.cluster_name
}

# -----------------------------------------------------------------------------
# Phase 1: EKS — Private Kubernetes Cluster with OIDC
# -----------------------------------------------------------------------------
module "eks" {
  source = "./modules/eks"

  project_name        = var.project_name
  environment         = var.environment
  cluster_name        = var.cluster_name
  cluster_version     = var.cluster_version
  vpc_id              = module.networking.vpc_id
  private_subnet_ids  = module.networking.private_subnet_ids
  node_instance_types = var.node_instance_types
  node_desired_size   = var.node_desired_size
  node_min_size       = var.node_min_size
  node_max_size       = var.node_max_size
}

# -----------------------------------------------------------------------------
# Phase 1: Security — IAM, KMS, IRSA, Cross-Account Roles
# -----------------------------------------------------------------------------
module "security" {
  source = "./modules/security"

  project_name      = var.project_name
  environment       = var.environment
  oidc_provider_arn = module.eks.oidc_provider_arn
  oidc_provider_url = module.eks.oidc_provider_url
  firehose_arn      = module.firehose.firehose_arn
}

# -----------------------------------------------------------------------------
# Phase 1: Log Ingestion — S3 + SQS Bridge for SIEM
# -----------------------------------------------------------------------------
module "log_ingestion" {
  source = "./modules/log-ingestion"

  project_name          = var.project_name
  environment           = var.environment
  kms_key_arn           = module.security.kms_key_arn
  kms_key_id            = module.security.kms_key_id
  log_retention_days    = var.log_retention_days
  sqs_message_retention = var.sqs_message_retention
  tenants               = var.tenants
}

# -----------------------------------------------------------------------------
# Phase 2: Firehose — Log Optimization Pipeline with Lambda
# -----------------------------------------------------------------------------
module "firehose" {
  source = "./modules/firehose"

  project_name       = var.project_name
  environment        = var.environment
  s3_bucket_arn      = module.log_ingestion.log_bucket_arn
  kms_key_arn        = module.security.kms_key_arn
  lambda_role_arn    = module.security.lambda_transformer_role_arn
  lambda_source_path = "${path.root}/../lambda/log_transformer.py"
}
