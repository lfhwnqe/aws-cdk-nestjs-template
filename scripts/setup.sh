#!/bin/bash

# Trade Management Backend Setup Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}[SETUP]${NC} $1"
}

print_header "Trade Management Backend Setup"
echo "========================================"

# Check if required tools are installed
print_status "Checking prerequisites..."

command -v node >/dev/null 2>&1 || { print_error "Node.js is required but not installed. Please install Node.js 18+ and try again."; exit 1; }
command -v npm >/dev/null 2>&1 || { print_error "npm is required but not installed. Please install npm and try again."; exit 1; }
command -v aws >/dev/null 2>&1 || { print_warning "AWS CLI not found. You'll need it for deployment."; }

# Check Node.js version
NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
if [[ $NODE_VERSION -lt 18 ]]; then
    print_error "Node.js version 18 or higher is required. Current version: $(node --version)"
    exit 1
fi

print_status "Node.js version: $(node --version) ✓"
print_status "npm version: $(npm --version) ✓"

# Install main project dependencies
print_status "Installing main project dependencies..."
npm install

# Install infrastructure dependencies
print_status "Installing infrastructure dependencies..."
cd infrastructure
npm install

# Install AWS CDK globally if not present
if ! command -v cdk >/dev/null 2>&1; then
    print_status "Installing AWS CDK globally..."
    npm install -g aws-cdk
else
    print_status "AWS CDK already installed: $(cdk --version)"
fi

cd ..

# Create environment files if they don't exist
print_status "Setting up environment configuration..."

if [[ ! -f ".env" ]]; then
    if [[ -f ".env.example" ]]; then
        cp .env.example .env
        print_status "Created .env from .env.example"
        print_warning "Please update .env with your actual configuration values"
    else
        print_warning ".env.example not found. Please create .env manually"
    fi
fi

# Make scripts executable
print_status "Making scripts executable..."
chmod +x scripts/*.sh

# Build the project
print_status "Building the project..."
npm run build

# Run tests to verify setup
print_status "Running tests to verify setup..."
npm run test

print_status "Setup completed successfully!"
echo ""
print_header "Next Steps:"
echo "1. Update .env file with your AWS credentials and configuration"
echo "2. Configure AWS CLI: aws configure"
echo "3. Bootstrap CDK (first time only): cd infrastructure && cdk bootstrap"
echo "4. Deploy to development: npm run deploy:dev"
echo "5. Start development server: npm run start:dev"
echo ""
print_header "Useful Commands:"
echo "• Start development server: npm run start:dev"
echo "• Run tests: npm run test"
echo "• Build project: npm run build"
echo "• Deploy to dev: npm run deploy:dev"
echo "• Deploy to prod: npm run deploy:prod"
echo "• View API docs: http://localhost:3000/api/v1/docs (after starting server)"
echo ""
print_status "Happy coding! 🚀"
