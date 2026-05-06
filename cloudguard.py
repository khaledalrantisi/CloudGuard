import boto3
import json
from datetime import datetime

print("=" * 55)
print("  CloudGuard - AWS Security Auditor")
print("  by Khaled M.M. Alrantisi")
print("=" * 55)

findings = []
summary = {"total_issues": 0, "critical": 0, "medium": 0, "low": 0}

# CHECK S3 BUCKETS
print("\n[*] Scanning S3 Buckets...")
try:
    s3 = boto3.client('s3')
    buckets = s3.list_buckets().get('Buckets', [])
    print(f"    Found {len(buckets)} bucket(s)")
    for bucket in buckets:
        name = bucket['Name']
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    findings.append({
                        "severity": "CRITICAL",
                        "service": "S3",
                        "resource": name,
                        "issue": "Bucket is publicly accessible",
                        "recommendation": "Remove public access from bucket ACL"
                    })
                    summary["critical"] += 1
                    summary["total_issues"] += 1
                    print(f"    [CRITICAL] {name} is PUBLIC")
        except Exception:
            pass
    if not buckets:
        print("    No S3 buckets found")
except Exception as e:
    print(f"    Error scanning S3: {e}")

# CHECK IAM USERS
print("\n[*] Scanning IAM Users...")
try:
    iam = boto3.client('iam')
    users = iam.list_users().get('Users', [])
    print(f"    Found {len(users)} user(s)")
    for user in users:
        username = user['UserName']
        mfa_devices = iam.list_mfa_devices(UserName=username).get('MFADevices', [])
        if not mfa_devices:
            findings.append({
                "severity": "CRITICAL",
                "service": "IAM",
                "resource": username,
                "issue": "User has no MFA enabled",
                "recommendation": "Enable MFA for all IAM users immediately"
            })
            summary["critical"] += 1
            summary["total_issues"] += 1
            print(f"    [CRITICAL] {username} has NO MFA")
        keys = iam.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
        for key in keys:
            created = key['CreateDate'].replace(tzinfo=None)
            age_days = (datetime.utcnow() - created).days
            if age_days > 90:
                findings.append({
                    "severity": "MEDIUM",
                    "service": "IAM",
                    "resource": username,
                    "issue": f"Access key is {age_days} days old",
                    "recommendation": "Rotate access keys every 90 days"
                })
                summary["medium"] += 1
                summary["total_issues"] += 1
                print(f"    [MEDIUM] {username} key is {age_days} days old")
except Exception as e:
    print(f"    Error scanning IAM: {e}")

# CHECK SECURITY GROUPS
print("\n[*] Scanning Security Groups...")
try:
    ec2 = boto3.client('ec2')
    sgs = ec2.describe_security_groups().get('SecurityGroups', [])
    print(f"    Found {len(sgs)} security group(s)")
    for sg in sgs:
        for perm in sg.get('IpPermissions', []):
            for ip_range in perm.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    port = perm.get('FromPort', 'ALL')
                    if port in [22, 3389]:
                        findings.append({
                            "severity": "CRITICAL",
                            "service": "EC2",
                            "resource": sg['GroupId'],
                            "issue": f"Port {port} open to the world (0.0.0.0/0)",
                            "recommendation": "Restrict access to specific IP ranges"
                        })
                        summary["critical"] += 1
                        summary["total_issues"] += 1
                        print(f"    [CRITICAL] {sg['GroupId']} port {port} open to world")
except Exception as e:
    print(f"    Error scanning Security Groups: {e}")

# GENERATE REPORT
print("\n" + "=" * 55)
print("  SECURITY REPORT SUMMARY")
print("=" * 55)
print(f"  Total Issues  : {summary['total_issues']}")
print(f"  Critical      : {summary['critical']}")
print(f"  Medium        : {summary['medium']}")
print(f"  Low           : {summary['low']}")

report = {
    "report_date": datetime.utcnow().isoformat(),
    "developer": "Khaled M.M. Alrantisi",
    "project": "CloudGuard",
    "summary": summary,
    "findings": findings
}

with open('security_report.json', 'w') as f:
    json.dump(report, f, indent=2)

print(f"\n  Report saved to: security_report.json")
print("=" * 55)

if summary['total_issues'] == 0:
    print("\n  [OK] No critical issues found. Your AWS is clean!")
else:
    print(f"\n  [!] {summary['total_issues']} issue(s) found. Check security_report.json")