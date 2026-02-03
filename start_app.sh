#!/bin/bash

echo ""
echo "============================================================"
echo "🚀 Certificate Authority - Quick Start Script"
echo "============================================================"
echo ""

# Check if MongoDB is running
if pgrep -f mongod > /dev/null; then
    echo "✅ MongoDB is running"
else
    echo "❌ MongoDB is NOT running"
    echo ""
    echo "Starting MongoDB..."
    brew services start mongodb-community
    echo "⏳ Waiting for MongoDB to start..."
    sleep 3
    
    if pgrep -f mongod > /dev/null; then
        echo "✅ MongoDB started successfully"
    else
        echo "❌ Failed to start MongoDB"
        echo "   Please start manually: brew services start mongodb-community"
        exit 1
    fi
fi

echo ""
echo "============================================================"
echo "🔐 Starting Certificate Authority Application"
echo "============================================================"
echo ""
echo "📍 URL: http://localhost:9000"
echo "📧 Default Admin: admin@certificate-authority.com"
echo "🔑 Default Password: Admin@Secure123"
echo ""
echo "✨ New Features:"
echo "   • Forgot Password - Working! 🎉"
echo "   • Fast startup with MongoDB timeout"
echo ""
echo "============================================================"
echo ""

# Activate virtual environment and run app
source venv/bin/activate
python3 app.py
