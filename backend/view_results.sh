#!/bin/bash

DOMAIN=${1:-terralogic.com}
FILE="/tmp/nightfall_${DOMAIN}.json"

if [ ! -f "$FILE" ]; then
    echo "❌ No results found for $DOMAIN"
    exit 1
fi

echo "🌙 NIGHTFALL TSUKUYOMI - Passive Reconnaissance Results"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🎯 Target: $DOMAIN"
echo "⏱️  Duration: $(jq -r '.duration_seconds' $FILE) seconds"
echo "📊 Modules: $(jq -r '.modules_executed' $FILE) executed, $(jq -r '.modules_succeeded' $FILE) succeeded"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📡 SUBDOMAINS DISCOVERED ($(jq '.subdomains | length' $FILE))"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
jq -r '.subdomains[] | "  ✓ \(.name) (via \(.source))"' $FILE | head -20
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🌐 DNS RECORDS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "A Records:"
jq -r '.dns_records.A[]? // empty | "  → \(.)"' $FILE
echo ""
echo "MX Records:"
jq -r '.dns_records.MX[]? // empty | "  → \(.)"' $FILE
echo ""
echo "TXT Records:"
jq -r '.dns_records.TXT[]? // empty | "  → \(.)"' $FILE | head -3
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔐 SSL CERTIFICATES ($(jq '.ssl_certificates | length' $FILE))"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
jq -r '.ssl_certificates[] | "  Subject: \(.subject)\n  Issuer: \(.issuer)\n  Valid Until: \(.valid_to)\n"' $FILE | head -15
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🌐 SOCIAL MEDIA PROFILES ($(jq '.social_profiles | length' $FILE))"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
jq -r '.social_profiles[] | "  \(.platform): \(.url)"' $FILE
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "☁️  CLOUD INFRASTRUCTURE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "S3 Buckets: $(jq '.s3_buckets | length' $FILE)"
jq -r '.s3_buckets[]? | "  → \(.name) (Public: \(.public))"' $FILE
echo ""
echo "Azure Resources: $(jq '.azure_resources | length' $FILE)"
jq -r '.azure_resources[]? | "  → \(.name)"' $FILE
echo ""
echo "GCP Resources: $(jq '.gcp_resources | length' $FILE)"
jq -r '.gcp_resources[]? | "  → \(.name)"' $FILE
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📜 HISTORICAL DATA"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Wayback Snapshots: $(jq '.wayback_snapshots | length' $FILE)"
jq -r '.wayback_snapshots[0:5][]? | "  \(.timestamp) - \(.url)"' $FILE
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 DATA SOURCES USED ($(jq '.data_sources | length' $FILE))"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
jq -r '.data_sources[] | "  ✓ \(.)"' $FILE
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📄 Full JSON results: $FILE"
echo "🌐 API endpoint: curl http://localhost:8888/api/v1/intel/passive/$DOMAIN | jq '.'"
echo ""
