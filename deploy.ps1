
Write-Host "🌙 NIGHTFALL TSUKUYOMI - Windows Docker Deployment" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# Check if Docker is running
if (!(Get-Process "com.docker.backend" -ErrorAction SilentlyContinue) -and !(Get-Process "Docker Desktop" -ErrorAction SilentlyContinue)) {
    Write-Host "⚠️ Docker is not running! Please start Docker Desktop first." -ForegroundColor Yellow
    exit 1
}

# Stop existing containers if running
Write-Host "🛑 Stopping existing services (if any)..." -ForegroundColor Yellow
docker-compose down 2>$null

# Build and start
Write-Host "🐳 Building Docker images..." -ForegroundColor Blue
docker-compose build --no-cache

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "🚀 Starting containers..." -ForegroundColor Green
docker-compose up -d

# Wait a bit for initialization
Write-Host "⏳ Waiting for services to initialize..." -ForegroundColor Yellow
Start-Sleep -Seconds 15

# Get Local IP
$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch "vEthernet|Loopback" } | Select-Object -First 1).IPAddress
if (-not $ip) { $ip = "localhost" }

Write-Host ""
Write-Host "📊 Container Status:" -ForegroundColor Cyan
docker-compose ps

Write-Host ""
Write-Host "✅ DEPLOYMENT COMPLETE!" -ForegroundColor Green
Write-Host ""
Write-Host "🌐 Access Points:" -ForegroundColor White
Write-Host "   Frontend: http://localhost (or http://$ip)" -ForegroundColor White
Write-Host "   Backend:  http://localhost:8080/health" -ForegroundColor White
Write-Host ""
Write-Host "📋 Useful Commands:" -ForegroundColor Gray
Write-Host "   View logs:    docker-compose logs -f"
Write-Host "   Stop:         docker-compose down"
Write-Host "   Restart:      docker-compose restart"
