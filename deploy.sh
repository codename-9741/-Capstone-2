#!/bin/bash

echo "🌙 NIGHTFALL TSUKUYOMI - Docker Deployment"
echo "==========================================="

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "⚠️ docker-compose could not be found. Please install it."
    exit 1
fi

# Stop existing services
echo "🛑 Stopping existing services..."
docker-compose down 2>/dev/null || true

# Build and start containers
echo "🐳 Building Docker images..."
docker-compose build --no-cache

if [ $? -ne 0 ]; then
    echo "❌ Build failed! Check Docker output above."
    exit 1
fi

echo "🚀 Starting containers..."
docker-compose up -d

echo "⏳ Waiting for services to start..."
sleep 15

# Check status
echo ""
echo "📊 Container Status:"
docker-compose ps

# Try to get local IP (Linux/MacOS)
IP=$(hostname -I | awk '{print $1}')
if [ -z "$IP" ]; then IP="localhost"; fi

echo ""
echo "✅ DEPLOYMENT COMPLETE!"
echo ""
echo "🌐 Access Points:"
echo "   Frontend: http://localhost (or http://$IP)"
echo "   Backend:  http://localhost:8080"
echo ""
echo "📋 Useful Commands:"
echo "   View logs:    docker-compose logs -f"
echo "   Stop:         docker-compose down"
echo "   Restart:      docker-compose restart"
echo "   Database:     docker-compose exec postgres psql -U nightfall -d nightfall"
