import type { Finding } from "@/lib/types";

export const FINDINGS: Finding[] = [
  {
    id: "f-101",
    title: "S3 bucket 'prod-customer-data' is publicly readable",
    description:
      "The bucket policy grants s3:GetObject to Principal '*' from 0.0.0.0/0, exposing customer PII to the internet. Amazon Macie flagged 1.2M sensitive records in the bucket.",
    service: "S3",
    category: "s3",
    provider: "aws",
    severity: "critical",
    confidence: 98,
    status: "open",
    evidence: "Bucket: s3://prod-customer-data | ACL: public-read | Policy: { Principal: *, Action: s3:GetObject, Effect: Allow }",
    affectedAsset: "prod-customer-data",
    detectedAt: "2026-08-03T09:14:00Z",
    framework: "CIS AWS 2.1.5",
    mitre: ["T1530"],
    terraform: `resource "aws_s3_bucket_acl" "prod_customer_data" {
  bucket = aws_s3_bucket.prod_customer_data.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "prod_customer_data" {
  bucket                  = aws_s3_bucket.prod_customer_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`,
    cli: `aws s3api put-bucket-acl --bucket prod-customer-data --acl private
aws s3api put-public-access-block --bucket prod-customer-data \\
  --public-access-block-configuration \\
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`,
    rollback: `aws s3api put-bucket-acl --bucket prod-customer-data --acl public-read`,
    autoFixable: true,
  },
  {
    id: "f-115",
    title: "GCP User-Managed Service Account Key exposed",
    description: "A user-managed JSON key for 'sa-ci-deploy' is detected. These keys do not expire automatically and pose a significant risk if leaked.",
    service: "IAM",
    category: "iam",
    provider: "gcp",
    severity: "critical",
    confidence: 100,
    status: "open",
    evidence: "Key ID: 3b1a... | Service Account: sa-ci-deploy@acme-prod.iam.gserviceaccount.com | Status: Active",
    affectedAsset: "sa-ci-deploy",
    detectedAt: "2026-08-04T10:15:00Z",
    framework: "CIS GCP 1.4",
    mitre: ["T1078.004"],
    terraform: `// Action: disable_gcp_service_account_key`,
    cli: `gcloud iam service-accounts keys disable 3b1a --iam-account=sa-ci-deploy@acme-prod.iam.gserviceaccount.com`,
    rollback: `gcloud iam service-accounts keys enable 3b1a --iam-account=sa-ci-deploy@acme-prod.iam.gserviceaccount.com`,
    autoFixable: true,
  },
  {
    id: "f-102",
    title: "IAM role 'ci-deploy-role' has AdministratorAccess policy attached",
    description:
      "A CI role with no MFA and no condition keys carries full administrative privileges. Compromise of the CI pipeline grants an attacker full control of the account.",
    service: "IAM",
    category: "iam",
    provider: "aws",
    severity: "critical",
    confidence: 96,
    status: "open",
    evidence: "Attached policies: AdministratorAccess (arn:aws:iam::aws:policy/AdministratorAccess) | Last used: 41s ago",
    affectedAsset: "ci-deploy-role",
    detectedAt: "2026-08-03T07:02:00Z",
    framework: "CIS AWS 1.16",
    mitre: ["T1078.004"],
    terraform: `resource "aws_iam_role_policy_attachment" "ci_deploy" {
  role       = aws_iam_role.ci_deploy.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_iam_role" "ci_deploy" {
  name = "ci-deploy-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = "arn:aws:iam::ACCOUNT:oidc-provider/token.actions.githubusercontent.com" }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" } }
    }]
  })
}`,
    cli: `aws iam detach-role-policy --role-name ci-deploy-role \\
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam attach-role-policy --role-name ci-deploy-role \\
  --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess`,
    rollback: `aws iam attach-role-policy --role-name ci-deploy-role \\
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`,
    autoFixable: true,
  },
  {
    id: "f-103",
    title: "Security group 'sg-web-lb' allows SSH from 0.0.0.0/0",
    description:
      "Port 22 is open to the entire internet on a production load balancer security group. This enables brute-force and unauthorized administrative access.",
    service: "EC2",
    category: "security-group",
    provider: "aws",
    severity: "high",
    confidence: 99,
    status: "remediating",
    evidence: "sg-web-lb | Inbound: tcp/22 from 0.0.0.0/0 (allow) | Ports 80,443 also open to 0.0.0.0/0",
    affectedAsset: "sg-web-lb",
    detectedAt: "2026-08-02T21:33:00Z",
    framework: "CIS AWS 4.1",
    mitre: ["T1190"],
    terraform: `resource "aws_security_group_rule" "ssh_corp" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/8"]
  security_group_id = aws_security_group.web_lb.id
}`,
    cli: `aws ec2 revoke-security-group-ingress --group-id sg-0a1b2c3d4e5f6a7b8 \\
  --protocol tcp --port 22 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id sg-0a1b2c3d4e5f6a7b8 \\
  --protocol tcp --port 22 --cidr 10.0.0.0/8`,
    rollback: `aws ec2 authorize-security-group-ingress --group-id sg-0a1b2c3d4e5f6a7b8 \\
  --protocol tcp --port 22 --cidr 0.0.0.0/0`,
    autoFixable: true,
  },
  {
    id: "f-104",
    title: "CloudTrail disabled in us-west-2 (legacy account)",
    description:
      "API activity in the legacy account's us-west-2 region is not being logged. Attackers routinely disable logging to avoid detection (MITRE T1562.008).",
    service: "CloudTrail",
    category: "cloudtrail",
    provider: "aws",
    severity: "high",
    confidence: 94,
    status: "open",
    evidence: "Trail 'acme-legacy-global' does not cover us-west-2 | Last event logged: 14d ago",
    affectedAsset: "legacy-7755",
    detectedAt: "2026-08-02T15:20:00Z",
    framework: "CIS AWS 2.1",
    mitre: ["T1562.008"],
    terraform: `resource "aws_cloudtrail" "legacy_global" {
  name                          = "acme-legacy-global"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}`,
    cli: `aws cloudtrail create-trail --name acme-legacy-global \\
  --s3-bucket-name acme-cloudtrail-logs \\
  --is-multi-region-trail --enable-log-file-validation`,
    rollback: `aws cloudtrail delete-trail --name acme-legacy-global`,
    autoFixable: false,
  },
  {
    id: "f-105",
    title: "Lambda 'orders-processor' runs with excessively permissive execution role",
    description:
      "The function execution role includes 'iam:PassRole' and 's3:*' on all resources. Principle of least privilege is violated.",
    service: "Lambda",
    category: "iam",
    provider: "aws",
    severity: "medium",
    confidence: 88,
    status: "open",
    evidence: "Role: orders-processor-role | Policies: s3:*, iam:PassRole | Last invoked: 4m ago",
    affectedAsset: "orders-processor",
    detectedAt: "2026-08-01T11:45:00Z",
    framework: "CIS AWS 1.16",
    mitre: ["T1078.004"],
    terraform: `resource "aws_iam_role_policy" "orders_processor" {
  name = "orders-processor-scoped"
  role = aws_iam_role.orders_processor.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "arn:aws:s3:::orders-ingress/*"
    }]
  })
}`,
    cli: `aws iam put-role-policy --role-name orders-processor-role \\
  --policy-name orders-processor-scoped --policy-document file://scoped.json`,
    rollback: `aws iam put-role-policy --role-name orders-processor-role \\
  --policy-name orders-processor-role-policy --policy-document file://original.json`,
    autoFixable: true,
  },
  {
    id: "f-106",
    title: "RDS 'db-orders-prod' does not enforce encryption at rest",
    description:
      "The production orders database is running with storage encryption disabled. Customer order data is stored unencrypted.",
    service: "RDS",
    category: "database",
    provider: "aws",
    severity: "high",
    confidence: 95,
    status: "open",
    evidence: "db-orders-prod | StorageEncrypted: false | Engine: postgres 16.3 | Multi-AZ: true",
    affectedAsset: "db-orders-prod",
    detectedAt: "2026-07-31T16:08:00Z",
    framework: "CIS AWS 2.3.1",
    mitre: [],
    terraform: `resource "aws_db_instance" "orders_prod" {
  engine            = "postgres"
  instance_class    = "db.r6g.large"
  storage_encrypted = true
  kms_key_id        = aws_kms_key.orders.id
  # NOTE: enabling encryption requires a snapshot restore
}`,
    cli: `aws rds modify-db-instance --db-instance-identifier db-orders-prod \\
  --storage-encrypted --kms-key-id alias/aws/rds`,
    rollback: `aws rds modify-db-instance --db-instance-identifier db-orders-prod \\
  --no-storage-encrypted`,
    autoFixable: false,
  },
  {
    id: "f-107",
    title: "Azure VM 'vm-payroll-prod' exposed to internet on RDP (3389)",
    description:
      "A production payroll VM is directly reachable from the internet on RDP without a jump host or Just-In-Time access.",
    service: "Azure VM",
    category: "security-group",
    provider: "azure",
    severity: "critical",
    confidence: 93,
    status: "open",
    evidence: "NSG: nsg-payroll | Rule 'RDP-Internet': Allow *:3389 from Internet | VM has public IP 20.84.11.7",
    affectedAsset: "vm-payroll-prod",
    detectedAt: "2026-07-31T09:02:00Z",
    framework: "CIS Azure 6.1",
    mitre: ["T1190"],
    terraform: `resource "azurerm_network_security_rule" "rdp_corp" {
  name                        = "RDP-CorpOnly"
  priority                    = 150
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefixes     = ["10.20.0.0/16"]
  destination_address_prefix  = "*"
  network_security_group_name = azurerm_network_security_group.payroll.name
  resource_group_name         = "acme-prod"
}`,
    cli: `az network nsg rule create --nsg-name nsg-payroll -g acme-prod \\
  --name RDP-CorpOnly --priority 150 --direction Inbound \\
  --access Allow --protocol Tcp --source-address-prefixes 10.20.0.0/16 \\
  --source-port-range '*' --destination-port-range 3389`,
    rollback: `az network nsg rule delete --nsg-name nsg-payroll -g acme-prod \\
  --name RDP-CorpOnly`,
    autoFixable: true,
  },
  {
    id: "f-108",
    title: "GKE cluster 'gke-model-serving' has Workload Identity disabled",
    description:
      "Pods use static service account keys instead of Workload Identity, increasing key-exposure risk across the ML serving fleet.",
    service: "GKE",
    category: "k8s",
    provider: "gcp",
    severity: "medium",
    confidence: 90,
    status: "open",
    evidence: "gke-model-serving | workload_identity: disabled | 42 service account key bindings found",
    affectedAsset: "gke-model-serving",
    detectedAt: "2026-07-30T13:27:00Z",
    framework: "CIS GKE 6.2",
    mitre: [],
    terraform: `resource "google_container_cluster" "model_serving" {
  name     = "gke-model-serving"
  location = "us-central1"
  workload_identity_config {
    workload_pool = "acme-data.svc.id.goog"
  }
}`,
    cli: `gcloud container clusters update gke-model-serving \\
  --region us-central1 --workload-pool acme-data.svc.id.goog`,
    rollback: `gcloud container clusters update gke-model-serving \\
  --region us-central1 --no-workload-pool`,
    autoFixable: false,
  },
  {
    id: "f-109",
    title: "EC2 'jenkins-legacy' running end-of-life kernel (RHEL 7.9)",
    description:
      "The legacy CI server runs a RHEL 7.9 kernel past end-of-life with 14 known critical CVEs, including CVE-2023-4911 (Looney Tunables).",
    service: "EC2",
    category: "ec2",
    provider: "aws",
    severity: "high",
    confidence: 91,
    status: "open",
    evidence: "os: RHEL 7.9 | kernel: 3.10.0-1160 | critical CVEs: 14 | missing patches: 38",
    affectedAsset: "jenkins-legacy",
    detectedAt: "2026-07-29T18:52:00Z",
    cve: "CVE-2023-4911",
    framework: "CIS AWS 4.4",
    mitre: ["T1210"],
    terraform: "",
    cli: `sudo yum update -y --security
sudo reboot`,
    rollback: "N/A — patch is reversible via AMI snapshot restore",
    autoFixable: false,
  },
  {
    id: "f-110",
    title: "CloudWatch log groups have no expiry — unlimited retention",
    description:
      "Security-relevant logs in the production account are retained indefinitely, inflating storage cost and complicating compliance e-discovery.",
    service: "CloudWatch",
    category: "cloudwatch",
    provider: "aws",
    severity: "low",
    confidence: 97,
    status: "acknowledged",
    evidence: "87 log groups with retention: NEVER_EXPIRE | largest: /aws/lambda/orders-processor (412 GB)",
    affectedAsset: "prod-9823",
    detectedAt: "2026-07-29T08:41:00Z",
    framework: "CIS AWS 3.1",
    mitre: [],
    terraform: `resource "aws_cloudwatch_log_group" "orders_processor" {
  name              = "/aws/lambda/orders-processor"
  retention_in_days = 90
}`,
    cli: `aws logs put-retention-policy --log-group-name /aws/lambda/orders-processor \\
  --retention-in-days 90`,
    rollback: `aws logs put-retention-policy --log-group-name /aws/lambda/orders-processor \\
  --retention-in-days 10950000`,
    autoFixable: true,
  },
  {
    id: "f-111",
    title: "Azure Key Vault 'vault-kv-prod' allows default network access",
    description:
      "The production Key Vault accepts connections from any network. Network ACLs should restrict access to trusted VNets.",
    service: "Key Vault",
    category: "security-group",
    provider: "azure",
    severity: "high",
    confidence: 89,
    status: "open",
    evidence: "vault-kv-prod | default_action: Allow | bypass: AzureServices",
    affectedAsset: "vault-kv-prod",
    detectedAt: "2026-07-28T14:03:00Z",
    framework: "CIS Azure 5.1.2",
    mitre: [],
    terraform: `resource "azurerm_key_vault" "prod" {
  name                = "vault-kv-prod"
  resource_group_name = "acme-prod"
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}`,
    cli: `az keyvault update --name vault-kv-prod \\
  --default-action Deny --bypass AzureServices`,
    rollback: `az keyvault update --name vault-kv-prod \\
  --default-action Allow --bypass AzureServices`,
    autoFixable: true,
  },
  {
    id: "f-112",
    title: "Service account 'sa-ml-sa-8841' has owner on project data-analytics",
    description:
      "A single ML service account holds the owner role on the analytics project. Key rotation or compromise would be catastrophic.",
    service: "IAM",
    category: "iam",
    provider: "gcp",
    severity: "high",
    confidence: 92,
    status: "open",
    evidence: "sa-ml-sa-8841 | roles/owner on data-analytics | last key created 210d ago",
    affectedAsset: "sa-ml-sa-8841",
    detectedAt: "2026-07-27T10:16:00Z",
    framework: "CIS GCP 1.8",
    mitre: ["T1098"],
    terraform: `resource "google_project_iam_member" "ml_editor" {
  project = "data-analytics"
  role    = "roles/editor"
  member  = "serviceAccount:sa-ml-sa-8841@data-analytics.iam.gserviceaccount.com"
}`,
    cli: `gcloud projects remove-iam-policy-binding data-analytics \\
  --member serviceAccount:sa-ml-sa-8841@data-analytics.iam.gserviceaccount.com \\
  --role roles/owner
gcloud projects add-iam-policy-binding data-analytics \\
  --member serviceAccount:sa-ml-sa-8841@data-analytics.iam.gserviceaccount.com \\
  --role roles/editor`,
    rollback: `gcloud projects add-iam-policy-binding data-analytics \\
  --member serviceAccount:sa-ml-sa-8841@data-analytics.iam.gserviceaccount.com \\
  --role roles/owner`,
    autoFixable: true,
  },
  {
    id: "f-113",
    title: "Unused IAM access keys over 180 days on 'svc-order-api'",
    description:
      "Long-lived access keys that have not been used for over 180 days increase the credential exposure window.",
    service: "IAM",
    category: "iam",
    provider: "aws",
    severity: "medium",
    confidence: 98,
    status: "open",
    evidence: "Key AKIA5F6G…9Q2C | last used: 213d ago | user: svc-order-api",
    affectedAsset: "svc-order-api",
    detectedAt: "2026-07-26T12:34:00Z",
    framework: "CIS AWS 1.14",
    mitre: [],
    terraform: "",
    cli: `aws iam delete-access-key --user-name svc-order-api \\
  --access-key-id AKIA5F6GEXAMPLE`,
    rollback: `aws iam create-access-key --user-name svc-order-api`,
    autoFixable: true,
  },
  {
    id: "f-114",
    title: "CloudSQL 'cloudsql-warehouse' allows any authorized network",
    description:
      "The analytics CloudSQL instance authorizes 0.0.0.0/0 as an authorized network, allowing any IP to attempt database connections.",
    service: "CloudSQL",
    category: "database",
    provider: "gcp",
    severity: "high",
    confidence: 95,
    status: "open",
    evidence: "cloudsql-warehouse | authorized_networks: [0.0.0.0/0] | ssl: required",
    affectedAsset: "cloudsql-warehouse",
    detectedAt: "2026-07-25T09:50:00Z",
    framework: "CIS GCP 6.1.3",
    mitre: ["T1190"],
    terraform: `resource "google_sql_database_instance" "warehouse" {
  name             = "cloudsql-warehouse"
  database_version = "POSTGRES_15"
  settings {
    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        name  = "analytics-vpc"
        value = "10.10.0.0/16"
      }
    }
  }
}`,
    cli: `gcloud sql instances patch cloudsql-warehouse \\
  --authorized-networks=10.10.0.0/16`,
    rollback: `gcloud sql instances patch cloudsql-warehouse \\
  --authorized-networks=0.0.0.0/0`,
    autoFixable: true,
  },
];
