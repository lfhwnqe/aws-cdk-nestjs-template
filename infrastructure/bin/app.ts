#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { LinuoAwsTemplateStack } from '../lib/linuo-aws-template-stack';

const app = new cdk.App();

// Get environment from context
const environment = app.node.tryGetContext('environment') || 'dev';

// Allow overriding stack name via context (preferred for scripts)
const stackNameFromContext = app.node.tryGetContext('stackName');

// Get project name; if stackName is provided, derive projectName from it when possible
const projectNameEnv = process.env.PROJECT_NAME;
let projectName = projectNameEnv || 'linuo-aws-template';
if (!projectNameEnv && typeof stackNameFromContext === 'string' && stackNameFromContext.length > 0) {
  // If stackName ends with -<environment>, strip it to get projectName
  const suffix = `-${environment}`;
  projectName = stackNameFromContext.endsWith(suffix)
    ? stackNameFromContext.slice(0, -suffix.length)
    : stackNameFromContext;
}

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

const finalStackName = (typeof stackNameFromContext === 'string' && stackNameFromContext.length > 0)
  ? stackNameFromContext
  : `${projectName}-${environment}`;

new LinuoAwsTemplateStack(app, `${projectName}-stack-${environment}`, {
  env: config,
  environment,
  projectName,
  stackName: finalStackName,
});

app.synth();
