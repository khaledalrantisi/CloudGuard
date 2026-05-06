*# CloudGuard — AWS Security Auditor*



*Automated AWS security auditing tool built with Python and boto3.*



*\*\*Developed by Khaled M.M. Alrantisi\*\**



*## What it does*

*- Scans S3 buckets for public access vulnerabilities*

*- Audits IAM users for missing MFA and old access keys*

*- Checks EC2 security groups for dangerous open ports*

*- Generates a full JSON security report with findings*



*## Technologies*

*- Python*

*- AWS boto3*

*- AWS S3, IAM, EC2*

*- GitHub Actions CI/CD*



*## How to run*

*```bash*

*pip install boto3*

*aws configure*

*python cloudguard.py*

*```*



*## Sample Output*

*```*

*\[CRITICAL] Security group port 22 open to world (0.0.0.0/0)*

*\[CRITICAL] IAM user has no MFA enabled*

*Report saved to: security\_report.json*

*```*

