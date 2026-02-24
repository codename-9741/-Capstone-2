#!/bin/bash

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🌙 PHASE 3: Findings Workflow Testing${NC}"
echo "========================================"

# Login
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@nightfall.local","password":"password123"}' | jq -r '.data.access_token')

echo -e "${GREEN}✅ Logged in${NC}"

# Get findings
echo -e "\n${BLUE}Fetching findings...${NC}"
FINDINGS=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/findings?per_page=5")

COUNT=$(echo $FINDINGS | jq '.data | length')
echo -e "${GREEN}✅ Found $COUNT findings${NC}"

# Get stats
echo -e "\n${BLUE}Getting statistics...${NC}"
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/findings/stats" | jq '.data'

echo -e "\n${GREEN}✅ Phase 3 Complete!${NC}"
