#!/usr/bin/env python3
"""Create an S3 bucket using AWS Signature V4 (no external deps)."""

import hashlib, hmac, datetime, urllib.request, urllib.error, sys

ENDPOINT = "http://localhost:9000"
ACCESS_KEY = "minioadmin"
SECRET_KEY = "minioadmin"
REGION = "us-east-1"
BUCKET = sys.argv[1] if len(sys.argv) > 1 else "testbucket"

def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

def get_signature_key(key, date_stamp, region, service):
    k = sign(("AWS4" + key).encode("utf-8"), date_stamp)
    k = sign(k, region)
    k = sign(k, service)
    return sign(k, "aws4_request")

now = datetime.datetime.utcnow()
datestamp = now.strftime("%Y%m%d")
amz_date = now.strftime("%Y%m%dT%H%M%SZ")

method = "PUT"
host = "localhost:9000"
canonical_uri = "/" + BUCKET
payload_hash = hashlib.sha256(b"").hexdigest()

canonical_headers = (
    f"host:{host}\n"
    f"x-amz-content-sha256:{payload_hash}\n"
    f"x-amz-date:{amz_date}\n"
)
signed_headers = "host;x-amz-content-sha256;x-amz-date"
canonical_request = (
    f"{method}\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
)

credential_scope = f"{datestamp}/{REGION}/s3/aws4_request"
string_to_sign = (
    f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
    + hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
)

signing_key = get_signature_key(SECRET_KEY, datestamp, REGION, "s3")
signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

auth_header = (
    f"AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/{credential_scope}, "
    f"SignedHeaders={signed_headers}, Signature={signature}"
)

url = f"{ENDPOINT}/{BUCKET}"
req = urllib.request.Request(url, method="PUT")
req.add_header("Host", host)
req.add_header("x-amz-date", amz_date)
req.add_header("x-amz-content-sha256", payload_hash)
req.add_header("Authorization", auth_header)
req.add_header("Content-Length", "0")

try:
    resp = urllib.request.urlopen(req)
    print(f"Bucket '{BUCKET}' created (HTTP {resp.status})")
except urllib.error.HTTPError as e:
    body = e.read().decode()
    if "BucketAlreadyOwnedByYou" in body:
        print(f"Bucket '{BUCKET}' already exists")
    else:
        print(f"Error: HTTP {e.code}: {body}", file=sys.stderr)
        sys.exit(1)