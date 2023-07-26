module "dev-vpc" {
  source  = "app.terraform.io/Rajhi-Kist/module/aws"
  version = "0.0.4"

  vpc_cidr_block                                      = var.vpc_cidr_block
  env                                                 = var.env
  region                                              = var.region
  name                                                = var.name
  public_subnets                                      = var.public_subnets
  private_subnets                                     = var.private_subnets
  container_insights_log_group_retention_days         = var.container_insights_log_group_retention_days
  container_insights_metrics_log_group_retention_days = var.container_insights_metrics_log_group_retention_days
  engine_version                                      = var.engine_version
  allowed_cidr_blocks                                 = var.allowed_cidr_blocks
  inbound_security_groups                             = var.inbound_security_groups
  multi-az-deployment                                 = var.multi-az-deployment
  monitoring_interval                                 = var.monitoring_interval
  instance_class                                      = var.instance_class
  backup_plan_schedule                                = var.backup_plan_schedule
  aurora_backup_plan_schedule                         = var.aurora_backup_plan_schedule
  backup_retention_period                             = var.backup_retention_period
  master_username                                     = var.master_username
  master_password                                     = var.master_password
  password                                            = var.password
  username                                            = var.username
  preferred_maintenance_window                        = var.preferred_maintenance_window
  auto_minor_version_upgrade                          = var.auto_minor_version_upgrade
  account_id                                          = var.account_id
  admin_sso_role_name                                 = var.admin_sso_role_name
  workers_roles                                       = var.workers_roles
  role_groups_mapping                                 = var.role_groups_mapping
  port                                                = var.port
  instance_count                                      = var.instance_count
  ecr_iam_principal                                   = var.ecr_iam_principal
  readonly_external_aws_iam_principals                = var.readonly_external_aws_iam_principals
  ecr_repository                                      = var.ecr_repository
  pullthroughcache_repositories                       = var.pullthroughcache_repositories
  create                                              = var.create
  tags                                                = var.tags
  prefix_separator                                    = var.prefix_separator

  // Cluster variables...
  cluster_name                               = var.cluster_name
  kubernetes_version                         = var.kubernetes_version
  cluster_enabled_log_types                  = var.cluster_enabled_log_types
  cluster_additional_security_group_ids      = var.cluster_additional_security_group_ids
  control_plane_subnet_ids                   = var.control_plane_subnet_ids
  subnet_ids                                 = var.subnet_ids
  cluster_endpoint_private_access            = var.cluster_endpoint_private_access
  cluster_endpoint_public_access             = var.cluster_endpoint_public_access
  cluster_endpoint_public_access_cidrs       = var.cluster_endpoint_public_access_cidrs
  cluster_ip_family                          = var.cluster_ip_family
  cluster_service_ipv4_cidr                  = var.cluster_service_ipv4_cidr
  cluster_service_ipv6_cidr                  = var.cluster_service_ipv6_cidr
  outpost_config                             = var.outpost_config
  cluster_encryption_config                  = var.cluster_encryption_config
  attach_cluster_encryption_policy           = var.attach_cluster_encryption_policy
  cluster_tags                               = var.cluster_tags
  create_cluster_primary_security_group_tags = var.create_cluster_primary_security_group_tags
  cluster_timeouts                           = var.cluster_timeouts
  capacity_type                              = var.capacity_type

  // KMS Key variables...
  create_kms_key                    = var.create_kms_key
  kms_key_description               = var.kms_key_description
  kms_key_deletion_window_in_days   = var.kms_key_deletion_window_in_days
  enable_kms_key_rotation           = var.enable_kms_key_rotation
  kms_key_enable_default_policy     = var.kms_key_enable_default_policy
  kms_key_owners                    = var.kms_key_owners
  kms_key_administrators            = var.kms_key_administrators
  kms_key_users                     = var.kms_key_users
  kms_key_service_users             = var.kms_key_service_users
  kms_key_source_policy_documents   = var.kms_key_source_policy_documents
  kms_key_override_policy_documents = var.kms_key_override_policy_documents
  kms_key_aliases                   = var.kms_key_aliases

  // CloudWatch Log Group variables...
  create_cloudwatch_log_group            = var.create_cloudwatch_log_group
  cloudwatch_log_group_retention_in_days = var.cloudwatch_log_group_retention_in_days
  cloudwatch_log_group_kms_key_id        = var.cloudwatch_log_group_kms_key_id

  // Cluster Security Group variables...
  create_cluster_security_group           = var.create_cluster_security_group
  cluster_security_group_id               = var.cluster_security_group_id
  vpc_id                                  = var.vpc_id
  cluster_security_group_name             = var.cluster_security_group_name
  cluster_security_group_use_name_prefix  = var.cluster_security_group_use_name_prefix
  cluster_security_group_description      = var.cluster_security_group_description
  cluster_security_group_additional_rules = var.cluster_security_group_additional_rules
  cluster_security_group_tags             = var.cluster_security_group_tags

  // EKS IPV6 CNI Policy variable...
  create_cni_ipv6_iam_policy = var.create_cni_ipv6_iam_policy

  // Node Security Group variables...
  create_node_security_group                   = var.create_node_security_group
  node_security_group_id                       = var.node_security_group_id
  node_security_group_name                     = var.node_security_group_name
  node_security_group_use_name_prefix          = var.node_security_group_use_name_prefix
  node_security_group_description              = var.node_security_group_description
  node_security_group_additional_rules         = var.node_security_group_additional_rules
  node_security_group_enable_recommended_rules = var.node_security_group_enable_recommended_rules
  node_security_group_tags                     = var.node_security_group_tags

  // Cluster IAM Role variables...
  create_iam_role               = var.create_iam_role
  iam_role_arn                  = var.iam_role_arn
  iam_role_name                 = var.iam_role_name
  iam_role_use_name_prefix      = var.iam_role_use_name_prefix
  iam_role_path                 = var.iam_role_path
  iam_role_description          = var.iam_role_description
  iam_role_permissions_boundary = var.iam_role_permissions_boundary
  iam_role_additional_policies  = var.iam_role_additional_policies
  cluster_iam_role_dns_suffix   = var.cluster_iam_role_dns_suffix
  iam_role_tags                 = var.iam_role_tags

  // Cluster Encryption Policy variables...
  cluster_encryption_policy_use_name_prefix = var.cluster_encryption_policy_use_name_prefix
  cluster_encryption_policy_name            = var.cluster_encryption_policy_name
  cluster_encryption_policy_description     = var.cluster_encryption_policy_description
  cluster_encryption_policy_path            = var.cluster_encryption_policy_path
  cluster_encryption_policy_tags            = var.cluster_encryption_policy_tags

  // aws-auth configmap variables...
  manage_aws_auth_configmap               = var.manage_aws_auth_configmap
  create_aws_auth_configmap               = var.create_aws_auth_configmap
  aws_auth_node_iam_role_arns_non_windows = var.aws_auth_node_iam_role_arns_non_windows
  aws_auth_node_iam_role_arns_windows     = var.aws_auth_node_iam_role_arns_windows
  aws_auth_roles                          = var.aws_auth_roles
  aws_auth_users                          = var.aws_auth_users
  aws_auth_accounts                       = var.aws_auth_accounts

  // Jumphost variables...
  eks_jumphost_instance_type = var.eks_jumphost_instance_type
  jumphost_desired_capacity  = var.jumphost_desired_capacity
  jumphost_max_size          = var.jumphost_max_size
  jumphost_min_size          = var.jumphost_min_size
  ec2-key-public-key         = var.ec2-key-public-key
}
