"""
ABEL123 :: CLOUD SENTINEL
AWS misconfiguration scanner + external API/endpoint security scanner.

- AWS checks use READ-ONLY boto3 calls only (whitelisted, see AWS_CHECKS).
- AWS credentials are taken from the incoming request, used only in-memory
  for the duration of that request, and are NEVER logged or persisted to disk.
- No destructive/mutating AWS calls exist anywhere in this file.
"""

import re
import ssl
import socket
import datetime
import ipaddress
from urllib.parse import urlparse

import requests
import boto3
from botocore.exceptions import ClientError, BotoCoreError, NoCredentialsError
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def finding(severity, title, detail, resource=""):
    return {
        "severity": severity,   # critical | high | medium | low | info
        "title": title,
        "detail": detail,
        "resource": resource,
    }


def make_session(creds):
    return boto3.session.Session(
        aws_access_key_id=creds.get("access_key"),
        aws_secret_access_key=creds.get("secret_key"),
        aws_session_token=creds.get("session_token") or None,
        region_name=creds.get("region") or "us-east-1",
    )


# --------------------------------------------------------------------------
# AWS checks (all read-only: Describe*, List*, Get*)
# --------------------------------------------------------------------------

def check_s3(session, findings):
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            name = b["Name"]
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    uri = grantee.get("URI", "")
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        findings.append(finding(
                            "critical",
                            "S3 bucket publicly accessible via ACL",
                            f"Bucket '{name}' grants '{grant.get('Permission')}' to {uri.split('/')[-1]}.",
                            name,
                        ))
            except ClientError:
                pass

            try:
                pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                if not all(pab.values()):
                    findings.append(finding(
                        "high",
                        "S3 Block Public Access not fully enabled",
                        f"Bucket '{name}' does not block all public access vectors.",
                        name,
                    ))
            except ClientError as e:
                if "NoSuchPublicAccessBlockConfiguration" in str(e):
                    findings.append(finding(
                        "high",
                        "S3 Block Public Access not configured",
                        f"Bucket '{name}' has no Public Access Block configuration at all.",
                        name,
                    ))

            try:
                enc = s3.get_bucket_encryption(Bucket=name)
            except ClientError as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    findings.append(finding(
                        "medium",
                        "S3 bucket without default encryption",
                        f"Bucket '{name}' has no default server-side encryption.",
                        name,
                    ))

            try:
                ver = s3.get_bucket_versioning(Bucket=name)
                if ver.get("Status") != "Enabled":
                    findings.append(finding(
                        "low",
                        "S3 versioning disabled",
                        f"Bucket '{name}' does not have versioning enabled (ransomware/accidental-delete risk).",
                        name,
                    ))
            except ClientError:
                pass
    except (ClientError, BotoCoreError) as e:
        findings.append(finding("info", "S3 scan skipped", str(e)))


def check_iam(session, findings):
    try:
        iam = session.client("iam")
        users = iam.list_users().get("Users", [])
        for u in users:
            uname = u["UserName"]
            mfa = iam.list_mfa_devices(UserName=uname).get("MFADevices", [])
            if not mfa:
                findings.append(finding(
                    "high",
                    "IAM user without MFA",
                    f"User '{uname}' has no MFA device registered.",
                    uname,
                ))
            keys = iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", [])
            for k in keys:
                if k["Status"] == "Active":
                    age = (datetime.datetime.now(datetime.timezone.utc) - k["CreateDate"]).days
                    if age > 90:
                        findings.append(finding(
                            "medium",
                            "IAM access key older than 90 days",
                            f"Key '{k['AccessKeyId']}' for user '{uname}' is {age} days old and should be rotated.",
                            uname,
                        ))
            attached = iam.list_attached_user_policies(UserName=uname).get("AttachedPolicies", [])
            for p in attached:
                if p["PolicyArn"].endswith("AdministratorAccess"):
                    findings.append(finding(
                        "critical",
                        "IAM user with AdministratorAccess",
                        f"User '{uname}' has the AdministratorAccess managed policy directly attached.",
                        uname,
                    ))

        try:
            summary = iam.get_account_summary()["SummaryMap"]
            if summary.get("AccountMFAEnabled", 0) == 0:
                findings.append(finding(
                    "critical",
                    "Root account has no MFA",
                    "The AWS account root user does not have MFA enabled.",
                    "root",
                ))
        except ClientError:
            pass
    except (ClientError, BotoCoreError) as e:
        findings.append(finding("info", "IAM scan skipped", str(e)))


def check_security_groups(session, findings):
    try:
        ec2 = session.client("ec2")
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        risky_ports = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"}
        for sg in sgs:
            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort")
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        if from_port in risky_ports:
                            findings.append(finding(
                                "critical",
                                f"{risky_ports[from_port]} open to the internet",
                                f"Security group '{sg['GroupId']}' ({sg.get('GroupName')}) allows 0.0.0.0/0 on port {from_port}.",
                                sg["GroupId"],
                            ))
                        elif from_port == -1 or from_port is None:
                            findings.append(finding(
                                "critical",
                                "All traffic open to the internet",
                                f"Security group '{sg['GroupId']}' allows ALL ports/protocols from 0.0.0.0/0.",
                                sg["GroupId"],
                            ))
                        else:
                            findings.append(finding(
                                "medium",
                                "Port open to the internet",
                                f"Security group '{sg['GroupId']}' allows 0.0.0.0/0 on port {from_port}.",
                                sg["GroupId"],
                            ))
    except (ClientError, BotoCoreError) as e:
        findings.append(finding("info", "Security group scan skipped", str(e)))


def check_ebs(session, findings):
    try:
        ec2 = session.client("ec2")
        vols = ec2.describe_volumes().get("Volumes", [])
        for v in vols:
            if not v.get("Encrypted", False):
                findings.append(finding(
                    "medium",
                    "Unencrypted EBS volume",
                    f"Volume '{v['VolumeId']}' is not encrypted at rest.",
                    v["VolumeId"],
                ))
    except (ClientError, BotoCoreError) as e:
        findings.append(finding("info", "EBS scan skipped", str(e)))


def check_rds(session, findings):
    try:
        rds = session.client("rds")
        instances = rds.describe_db_instances().get("DBInstances", [])
        for db in instances:
            if db.get("PubliclyAccessible"):
                findings.append(finding(
                    "critical",
                    "RDS instance publicly accessible",
                    f"Database '{db['DBInstanceIdentifier']}' is reachable from the public internet.",
                    db["DBInstanceIdentifier"],
                ))
            if not db.get("StorageEncrypted", False):
                findings.append(finding(
                    "medium",
                    "RDS storage not encrypted",
                    f"Database '{db['DBInstanceIdentifier']}' has no encryption at rest.",
                    db["DBInstanceIdentifier"],
                ))
    except (ClientError, BotoCoreError) as e:
        findings.append(finding("info", "RDS scan skipped", str(e)))


def check_cloudtrail(session, findings):
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails().get("trailList", [])
        if not trails:
            findings.append(finding(
                "high",
                "No CloudTrail trail configured",
                "No CloudTrail trail exists in this region — API activity is not being logged.",
                "cloudtrail",
            ))
        else:
            for t in trails:
                if not t.get("IsMultiRegionTrail"):
                    findings.append(finding(
                        "low",
                        "CloudTrail trail is not multi-region",
                        f"Trail '{t.get('Name')}' only logs a single region.",
                        t.get("Name", ""),
                    ))
    except (ClientError, BotoCoreError) as e:
        findings.append(finding("info", "CloudTrail scan skipped", str(e)))


AWS_CHECKS = [
    ("S3 Buckets", check_s3),
    ("IAM", check_iam),
    ("Security Groups", check_security_groups),
    ("EBS Volumes", check_ebs),
    ("RDS", check_rds),
    ("CloudTrail", check_cloudtrail),
]


@app.route("/api/scan/aws", methods=["POST"])
def scan_aws():
    data = request.get_json(force=True) or {}
    creds = {
        "access_key": data.get("access_key", "").strip(),
        "secret_key": data.get("secret_key", "").strip(),
        "session_token": data.get("session_token", "").strip(),
        "region": data.get("region", "us-east-1").strip(),
    }
    if not creds["access_key"] or not creds["secret_key"]:
        return jsonify({"error": "access_key en secret_key zijn verplicht."}), 400

    selected = data.get("checks") or [name for name, _ in AWS_CHECKS]

    try:
        session = make_session(creds)
        # Sanity check credentials before running full scan
        sts = session.client("sts")
        identity = sts.get_caller_identity()
    except (NoCredentialsError, ClientError, BotoCoreError) as e:
        return jsonify({"error": f"AWS authenticatie mislukt: {str(e)}"}), 401

    findings = []
    ran = []
    for name, check_fn in AWS_CHECKS:
        if name in selected:
            check_fn(session, findings)
            ran.append(name)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 5))

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return jsonify({
        "account_id": identity.get("Account"),
        "identity_arn": identity.get("Arn"),
        "checks_run": ran,
        "counts": counts,
        "findings": findings,
        "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
    })


# --------------------------------------------------------------------------
# External API / endpoint scanner (safe, non-intrusive HTTP checks only)
# --------------------------------------------------------------------------

PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
]


def is_private_host(hostname):
    try:
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if any(ip in net for net in PRIVATE_NETS):
                return True
        return False
    except socket.gaierror:
        return True  # can't resolve -> block, safer default


SECURITY_HEADERS = {
    "Strict-Transport-Security": ("high", "HSTS ontbreekt — verbindingen kunnen naar HTTP gedowngraded worden."),
    "Content-Security-Policy": ("medium", "CSP ontbreekt — verhoogt risico op XSS."),
    "X-Content-Type-Options": ("low", "X-Content-Type-Options ontbreekt — MIME-sniffing mogelijk."),
    "X-Frame-Options": ("medium", "X-Frame-Options ontbreekt — clickjacking risico."),
    "Referrer-Policy": ("low", "Referrer-Policy ontbreekt — referrer data kan lekken."),
    "Permissions-Policy": ("low", "Permissions-Policy ontbreekt."),
}


def check_ssl_cert(hostname, port=443):
    findings = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (not_after - datetime.datetime.utcnow()).days
                if days_left < 0:
                    findings.append(finding("critical", "TLS-certificaat verlopen", f"Certificaat verliep {abs(days_left)} dagen geleden."))
                elif days_left < 14:
                    findings.append(finding("high", "TLS-certificaat verloopt binnenkort", f"Nog maar {days_left} dagen geldig."))
                cipher = ssock.cipher()
                if cipher and ("RC4" in cipher[0] or "3DES" in cipher[0]):
                    findings.append(finding("high", "Zwakke cipher suite", f"Server gebruikt {cipher[0]}."))
    except ssl.SSLCertVerificationError as e:
        findings.append(finding("critical", "TLS-certificaat validatie mislukt", str(e)))
    except Exception as e:
        findings.append(finding("info", "TLS-check kon niet worden uitgevoerd", str(e)))
    return findings


@app.route("/api/scan/endpoint", methods=["POST"])
def scan_endpoint():
    data = request.get_json(force=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url is verplicht."}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return jsonify({"error": "Ongeldige URL."}), 400

    if is_private_host(hostname):
        return jsonify({"error": "Scannen van private/lokale/onbekende hosts is niet toegestaan."}), 400

    findings = []

    try:
        resp = requests.get(url, timeout=8, allow_redirects=True)
    except requests.exceptions.SSLError as e:
        findings.append(finding("high", "SSL/TLS fout bij verbinden", str(e)))
        resp = None
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Kon endpoint niet bereiken: {str(e)}"}), 400

    headers = {}
    if resp is not None:
        headers = dict(resp.headers)

        for h, (sev, msg) in SECURITY_HEADERS.items():
            if h not in headers:
                findings.append(finding(sev, f"Header ontbreekt: {h}", msg))

        server = headers.get("Server", "")
        if server:
            findings.append(finding("low", "Server header lekt software-info", f"Server header: '{server}'."))
        x_powered = headers.get("X-Powered-By", "")
        if x_powered:
            findings.append(finding("low", "X-Powered-By header lekt software-info", f"X-Powered-By: '{x_powered}'."))

        acao = headers.get("Access-Control-Allow-Origin", "")
        if acao == "*":
            findings.append(finding("medium", "CORS wildcard toegestaan", "Access-Control-Allow-Origin is '*', elke origin mag deze API benaderen."))

        if parsed.scheme == "http":
            findings.append(finding("high", "Geen HTTPS", "Endpoint is bereikbaar over onversleuteld HTTP."))

        try:
            opt_resp = requests.options(url, timeout=6)
            allow = opt_resp.headers.get("Allow", "")
            dangerous = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in allow.upper()]
            if dangerous:
                findings.append(finding("medium", "Mogelijk gevaarlijke HTTP-methodes toegestaan", f"OPTIONS geeft aan: {allow}"))
        except requests.exceptions.RequestException:
            pass

        if resp.status_code >= 500:
            findings.append(finding("low", "Server error bij eerste request", f"Status code: {resp.status_code}"))

    if parsed.scheme == "https":
        findings.extend(check_ssl_cert(hostname, parsed.port or 443))

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 5))
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return jsonify({
        "url": url,
        "status_code": resp.status_code if resp is not None else None,
        "headers_seen": headers,
        "counts": counts,
        "findings": findings,
        "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
    })


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5012, debug=True)
