# CloudGuard Infrastructure
# Author: Khaled M.M. Alrantisi
# Defines AWS infrastructure that CloudGuard monitors

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# VPC
resource "aws_vpc" "cloudguard_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "cloudguard-vpc"
    Project     = "CloudGuard"
    Developer   = "Khaled M.M. Alrantisi"
    Environment = var.environment
  }
}

# Public Subnet
resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.cloudguard_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name    = "cloudguard-public-subnet"
    Project = "CloudGuard"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.cloudguard_vpc.id

  tags = {
    Name    = "cloudguard-igw"
    Project = "CloudGuard"
  }
}

# Route Table
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.cloudguard_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name    = "cloudguard-public-rt"
    Project = "CloudGuard"
  }
}

resource "aws_route_table_association" "public_rta" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

# Security Group — SECURE (no open ports to world)
resource "aws_security_group" "cloudguard_sg" {
  name        = "cloudguard-sg"
  description = "CloudGuard secure security group"
  vpc_id      = aws_vpc.cloudguard_vpc.id

  ingress {
    description = "HTTPS only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "cloudguard-sg"
    Project = "CloudGuard"
  }
}

# S3 Bucket — private and encrypted
resource "aws_s3_bucket" "cloudguard_reports" {
  bucket = "${var.project_name}-security-reports-${var.environment}"

  tags = {
    Name        = "cloudguard-reports"
    Project     = "CloudGuard"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_public_access_block" "reports_pab" {
  bucket = aws_s3_bucket.cloudguard_reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports_sse" {
  bucket = aws_s3_bucket.cloudguard_reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# IAM Role for CloudGuard
resource "aws_iam_role" "cloudguard_role" {
  name = "cloudguard-auditor-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name    = "cloudguard-role"
    Project = "CloudGuard"
  }
}

# IAM Policy — read only security auditing
resource "aws_iam_policy" "cloudguard_policy" {
  name        = "cloudguard-audit-policy"
  description = "Read-only policy for CloudGuard security auditing"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "s3:GetBucketAcl",
          "s3:GetBucketVersioning",
          "iam:ListUsers",
          "iam:ListMFADevices",
          "iam:ListAccessKeys",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cloudguard_attach" {
  role       = aws_iam_role.cloudguard_role.name
  policy_arn = aws_iam_policy.cloudguard_policy.arn
}