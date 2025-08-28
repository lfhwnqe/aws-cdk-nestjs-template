#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { TradeManageStack } from '../lib/trade-manage-stack';

const app = new cdk.App();

// Get environment from context
const environment = app.node.tryGetContext('environment') || 'dev';

// Environment-specific configuration
const envConfig: Record<string, { account?: string; region: string }> = {
  dev: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: 'ap-southeast-1',
    // region: process.env.CDK_DEFAULT_REGION || 'ap-southeast-1',
  },
  prod: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: 'ap-southeast-1',
    // region: process.env.CDK_DEFAULT_REGION || 'ap-southeast-1',
  },
};

const config = envConfig[environment];

if (!config) {
  throw new Error(`Unknown environment: ${environment}. Use 'dev' or 'prod'.`);
}

new TradeManageStack(app, `TradeManageStack-${environment}`, {
  env: config,
  environment,
  stackName: `trade-manage-${environment}`,
});

app.synth();
