#!/bin/bash

BASE_URL="http://localhost:8080"
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🌙 NIGHTFALL TSUKUYOMI - Authentication Testing${NC}"
echo "=================================================="
echo ""

# Test 1: Health Check
echo -e "${BLUE}Test 1: Health Check${NC}"
HEALTH=$(curl -s $BASE_URL/health)
if [[ $HEALTH == *"healthy"* ]]; then
    echo -e "${GREEN}✅ Health check passed${NC}"
else
    echo -e "${RED}❌ Health check failed${NC}"
    exit 1
fi
echo ""

# Test 2: Register
echo -e "${BLUE}Test 2: Register New User${NC}"
REGISTER=$(curl -s -X POST $BASE_URL/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test'$RANDOM'@nightfall.local","password":"password123","full_name":"Test User"}')

if [[ $REGISTER == *"success"* ]]; then
    echo -e "${GREEN}✅ User registration successful${NC}"
    echo "$REGISTER"
else
    echo -e "${RED}❌ Registration failed (might already exist)${NC}"
    echo "$REGISTER"
fi
echo ""

# Test 3: Login
echo -e "${BLUE}Test 3: Login${NC}"
LOGIN=$(curl -s -X POST $BASE_URL/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"analyst@nightfall.local","password":"nightfall123"}')

if [[ $LOGIN == *"access_token"* ]]; then
    echo -e "${GREEN}✅ Login successful${NC}"
    # Extract token (basic method without jq)
    TOKEN=$(echo $LOGIN | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
    echo "Token length: ${#TOKEN} characters"
else
    echo -e "${RED}❌ Login failed${NC}"
    echo "$LOGIN"
    exit 1
fi
echo ""

# Test 4: Protected Route
echo -e "${BLUE}Test 4: Access Protected Route${NC}"
if [ -z "$TOKEN" ]; then
    echo -e "${RED}❌ No token available${NC}"
    exit 1
fi

ME=$(curl -s -H "Authorization: Bearer $TOKEN" $BASE_URL/api/v1/auth/me)
if [[ $ME == *"success"* ]]; then
    echo -e "${GREEN}✅ Protected route access successful${NC}"
    echo "$ME"
else
    echo -e "${RED}❌ Protected route access failed${NC}"
    echo "$ME"
fi
echo ""

# Test 5: Unauthorized Access
echo -e "${BLUE}Test 5: Unauthorized Access (Should Fail)${NC}"
UNAUTH=$(curl -s $BASE_URL/api/v1/auth/me)
if [[ $UNAUTH == *"error"* ]] || [[ $UNAUTH == *"Authorization"* ]]; then
    echo -e "${GREEN}✅ Correctly blocked unauthorized access${NC}"
else
    echo -e "${RED}❌ Should have blocked this request${NC}"
fi
echo ""

echo "=================================================="
echo -e "${GREEN}✅ Authentication System Test Complete!${NC}"
