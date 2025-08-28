#!/bin/bash

# Clean script for trade-manage-backend
# This script removes all build artifacts and compiled files

set -e

echo "🧹 Cleaning build artifacts..."

# Remove main build outputs
if [ -d "dist" ]; then
    echo "  Removing dist/ directory..."
    rm -rf dist
fi
if [ -d "backend/build" ]; then
    echo "  Removing backend/build/ directory..."
    rm -rf backend/build
fi

# Remove lambda package
if [ -d "lambda-package" ]; then
    echo "  Removing lambda-package/ directory..."
    rm -rf lambda-package
fi

# Remove lambda temp build
if [ -d "lambda-temp-build" ]; then
    echo "  Removing lambda-temp-build/ directory..."
    rm -rf lambda-temp-build
fi

# Remove CDK output
if [ -d "infrastructure/cdk.out" ]; then
    echo "  Removing infrastructure/cdk.out/ directory..."
    rm -rf infrastructure/cdk.out
fi

# Remove CDK compiled files
if [ -f "infrastructure/bin/app.js" ]; then
    echo "  Removing infrastructure/bin/app.js..."
    rm -f infrastructure/bin/app.js
fi

if [ -f "infrastructure/bin/app.d.ts" ]; then
    echo "  Removing infrastructure/bin/app.d.ts..."
    rm -f infrastructure/bin/app.d.ts
fi

# Remove CDK lib compiled files
if [ -d "infrastructure/lib" ]; then
    echo "  Removing CDK lib compiled files..."
    find infrastructure/lib -name "*.js" -delete
    find infrastructure/lib -name "*.d.ts" -delete
fi

# Remove TypeScript build info files
echo "  Removing TypeScript build info files..."
find . -name "*.tsbuildinfo" -delete

# Remove coverage reports
if [ -d "coverage" ]; then
    echo "  Removing coverage/ directory..."
    rm -rf coverage
fi

# Remove test output
if [ -d ".nyc_output" ]; then
    echo "  Removing .nyc_output/ directory..."
    rm -rf .nyc_output
fi

# Remove temporary files
echo "  Removing temporary files..."
find . -name "*.tmp" -delete
find . -name "*.temp" -delete

echo "✅ Clean completed successfully!"
echo ""
echo "📝 Note: To rebuild the project, run:"
echo "  npm run build                 # Build NestJS app"
echo "  npm run build:lambda          # Build Lambda package"
echo "  cd infrastructure && npm run build  # Build CDK"
