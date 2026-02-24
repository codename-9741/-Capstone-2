#!/bin/bash

# Find and replace token expiration in auth service
sed -i 's/15 \* time.Minute/24 \* time.Hour/g' internal/services/auth_service.go
sed -i 's/7 \* 24 \* time.Hour/30 \* 24 \* time.Hour/g' internal/services/auth_service.go

echo "✅ Token expiration increased:"
echo "  - Access token: 24 hours (was 15 minutes)"
echo "  - Refresh token: 30 days (was 7 days)"
