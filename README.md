# ABEL123 :: CLOUD SENTINEL

AWS misconfig scanner + externe API/endpoint scanner.

## Starten

```bash
pip install -r requirements.txt
python app.py
```

Backend draait op `http://localhost:5000`. Open `index.html` in de browser
(of serveer via een simpele static server) — hij praat met de backend op
`API_BASE` in `script.js`.

## AWS credentials

Gebruik bij voorkeur een **read-only IAM user**. Minimaal benodigde
managed policy: `ReadOnlyAccess`, of een custom policy met:

- `s3:ListAllMyBuckets`, `s3:GetBucketAcl`, `s3:GetPublicAccessBlock`,
  `s3:GetBucketEncryption`, `s3:GetBucketVersioning`
- `iam:ListUsers`, `iam:ListMFADevices`, `iam:ListAccessKeys`,
  `iam:ListAttachedUserPolicies`, `iam:GetAccountSummary`
- `ec2:DescribeSecurityGroups`, `ec2:DescribeVolumes`
- `rds:DescribeDBInstances`
- `cloudtrail:DescribeTrails`
- `sts:GetCallerIdentity`

Credentials worden **niet gelogd of opgeslagen** — ze worden alleen
per request in-memory gebruikt om een boto3-sessie op te zetten.

Alle AWS-calls in `app.py` zijn read-only (`Describe*`, `List*`, `Get*`).
Er zit geen enkele destructieve/mutating call in de code.

## Endpoint scanner

Non-intrusieve checks: security headers, CORS, TLS-certificaat geldigheid,
HTTP-methodes via OPTIONS. Blokkeert scans naar private/lokale IP-ranges
(127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, etc).

Scan alleen endpoints waarvoor je toestemming hebt.
