#!/bin/bash

# Trade Management Backend Deployment Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
ENVIRONMENT="dev"
SKIP_BUILD=false
SKIP_TESTS=false

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

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -e, --environment ENV    Deployment environment (dev|prod) [default: dev]"
    echo "  -s, --skip-build        Skip build process"
    echo "  -t, --skip-tests        Skip running tests"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -e dev                Deploy to development environment"
    echo "  $0 -e prod               Deploy to production environment"
    echo "  $0 -e dev -s -t          Deploy to dev, skip build and tests"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -s|--skip-build)
            SKIP_BUILD=true
            shift
            ;;
        -t|--skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validate environment
if [[ "$ENVIRONMENT" != "dev" && "$ENVIRONMENT" != "prod" ]]; then
    print_error "Invalid environment: $ENVIRONMENT. Must be 'dev' or 'prod'"
    exit 1
fi

print_status "Starting deployment to $ENVIRONMENT environment..."

# Check if required tools are installed
command -v node >/dev/null 2>&1 || { print_error "Node.js is required but not installed. Aborting."; exit 1; }
command -v npm >/dev/null 2>&1 || { print_error "npm is required but not installed. Aborting."; exit 1; }

# Check if we're in the correct directory
if [[ ! -f "package.json" ]]; then
    print_error "package.json not found. Please run this script from the project root directory."
    exit 1
fi

# Install dependencies
print_status "Installing dependencies..."
npm ci

# Run tests (unless skipped)
if [[ "$SKIP_TESTS" == false ]]; then
    print_status "Running tests..."
    npm run test
    npm run test:e2e
fi

# Build the application (unless skipped)
if [[ "$SKIP_BUILD" == false ]]; then
    print_status "Building Lambda package..."
    npm run build:lambda
fi

# Set environment-specific configuration
print_status "Setting up environment configuration..."
if [[ -f ".env.$ENVIRONMENT" ]]; then
    cp ".env.$ENVIRONMENT" ".env"
    print_status "Environment configuration loaded from .env.$ENVIRONMENT"
else
    print_warning "No environment-specific configuration found (.env.$ENVIRONMENT)"
fi

# Deploy infrastructure with CDK
print_status "Deploying infrastructure..."
cd infrastructure

# Install CDK dependencies
npm ci

# Deploy CDK stack
print_status "Deploying CDK stack for $ENVIRONMENT environment..."
npm run cdk deploy -- --context environment=$ENVIRONMENT --require-approval never

cd ..

print_status "Deployment completed successfully!"
print_status "Environment: $ENVIRONMENT"

# Show next steps
echo ""
print_status "Next steps:"
echo "1. Verify the deployment in AWS Console"
echo "2. Test the API endpoints"
echo "3. Monitor application logs"

if [[ "$ENVIRONMENT" == "prod" ]]; then
    print_warning "Production deployment completed. Please monitor the application closely."
fi
