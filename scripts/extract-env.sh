#!/bin/bash

# Extract environment variables from CDK output
# This script helps extract the .env format from CDK deployment output

set -e

echo "🔧 Extracting environment variables from CDK output..."

# Check if CDK output file exists
CDK_OUTPUT_FILE="infrastructure/cdk.out/outputs.json"

if [ ! -f "$CDK_OUTPUT_FILE" ]; then
    echo "❌ CDK output file not found. Please run 'cdk deploy' first."
    exit 1
fi

# Extract the EnvVars output
ENV_VARS=$(cat "$CDK_OUTPUT_FILE" | jq -r '.["TradeManageStack-dev"].EnvVars // empty')

if [ -z "$ENV_VARS" ]; then
    echo "❌ EnvVars output not found in CDK output."
    echo "💡 Make sure you have deployed the stack with the updated CDK configuration."
    exit 1
fi

# Create .env file
echo "📝 Creating .env file..."
echo "$ENV_VARS" > .env

echo "✅ Environment variables extracted successfully!"
echo "📄 .env file created with the following content:"
echo ""
echo "--- .env file content ---"
cat .env
echo "--- end of .env file ---"
echo ""
echo "🎯 You can now use this .env file for local development."
echo "💡 Remember to set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY for local development."
