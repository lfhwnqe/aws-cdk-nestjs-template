#!/bin/bash

# Trade Management Backend Development Script

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[DEV]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  start       Start development server with hot reload"
    echo "  test        Run tests in watch mode"
    echo "  lint        Run linter and fix issues"
    echo "  format      Format code with Prettier"
    echo "  clean       Clean build artifacts"
    echo "  reset       Reset node_modules and reinstall"
    echo "  docs        Open API documentation"
    echo ""
    echo "Examples:"
    echo "  $0 start     Start development server"
    echo "  $0 test      Run tests in watch mode"
    echo "  $0 lint      Lint and fix code"
}

# Default command
COMMAND=${1:-start}

case $COMMAND in
    start)
        print_status "Starting development server..."
        print_info "API will be available at: http://localhost:3000/api/v1"
        print_info "API docs will be available at: http://localhost:3000/api/v1/docs"
        print_info "Press Ctrl+C to stop the server"
        echo ""
        
        # Load development environment
        if [[ -f ".env.development" ]]; then
            export $(cat .env.development | grep -v '^#' | xargs)
        fi
        
        npm run start:dev
        ;;
    
    test)
        print_status "Running tests in watch mode..."
        npm run test:watch
        ;;
    
    lint)
        print_status "Running linter..."
        npm run lint
        ;;
    
    format)
        print_status "Formatting code..."
        npm run format
        ;;
    
    clean)
        print_status "Cleaning build artifacts..."
        rm -rf dist/
        rm -rf coverage/
        rm -rf node_modules/.cache/
        print_status "Clean completed"
        ;;
    
    reset)
        print_status "Resetting node_modules..."
        rm -rf node_modules/
        rm -f package-lock.json
        npm install
        print_status "Reset completed"
        ;;
    
    docs)
        print_status "Opening API documentation..."
        if command -v open >/dev/null 2>&1; then
            open http://localhost:3000/api/v1/docs
        elif command -v xdg-open >/dev/null 2>&1; then
            xdg-open http://localhost:3000/api/v1/docs
        else
            print_info "Please open http://localhost:3000/api/v1/docs in your browser"
        fi
        ;;
    
    -h|--help|help)
        show_usage
        ;;
    
    *)
        echo "Unknown command: $COMMAND"
        show_usage
        exit 1
        ;;
esac
