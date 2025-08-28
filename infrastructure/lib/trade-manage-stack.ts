import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import { Construct } from 'constructs';
import * as path from 'path';

export interface TradeManageStackProps extends cdk.StackProps {
  environment: string;
  stackName: string;
}

export class TradeManageStack extends cdk.Stack {
  public readonly s3Bucket: s3.Bucket;
  public readonly importExportBucket: s3.Bucket;
  public readonly userPool: cognito.UserPool;
  public readonly userPoolClient: cognito.UserPoolClient;
  public readonly usersTable: dynamodb.Table;
  public readonly tradesTable: dynamodb.Table;
  public readonly filesTable: dynamodb.Table;
  // New tables for financial product management
  public readonly customersTable: dynamodb.Table;
  public readonly productsTable: dynamodb.Table;
  public readonly customerProductTransactionsTable: dynamodb.Table;
  public readonly apiLambda: lambda.Function;
  public readonly api: apigateway.RestApi;

  constructor(scope: Construct, id: string, props: TradeManageStackProps) {
    super(scope, id, props);

    const { environment } = props;

    // S3 Bucket for file storage
    this.s3Bucket = new s3.Bucket(this, 'FilesBucket', {
      bucketName: `trade-manage-files-${environment}-${this.region}`,
      versioned: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      cors: [
        {
          allowedMethods: [
            s3.HttpMethods.GET,
            s3.HttpMethods.POST,
            s3.HttpMethods.PUT,
            s3.HttpMethods.DELETE,
          ],
          allowedOrigins: ['*'],
          allowedHeaders: ['*'],
        },
      ],
      lifecycleRules: [
        {
          id: 'DeleteIncompleteMultipartUploads',
          abortIncompleteMultipartUploadAfter: cdk.Duration.days(7),
        },
      ],
      removalPolicy: environment === 'prod' ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });

    // S3 Bucket for import/export temporary files
    this.importExportBucket = new s3.Bucket(this, 'ImportExportBucket', {
      bucketName: `trade-manage-import-export-${environment}-${this.region}`,
      // Temporary files: no versioning to avoid keeping stale versions
      versioned: false,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      cors: [
        {
          // Pre-signed URL flow needs GET/PUT/HEAD
          allowedMethods: [s3.HttpMethods.GET, s3.HttpMethods.PUT, s3.HttpMethods.HEAD],
          allowedOrigins: ['*'], // TODO: restrict to frontend origins when available
          allowedHeaders: ['*'],
          exposedHeaders: ['ETag', 'x-amz-request-id'],
        },
      ],
      lifecycleRules: [
        {
          id: 'ExpireTemporaryObjects',
          expiration: cdk.Duration.days(7), // Auto-delete after 7 days
        },
        {
          id: 'AbortIncompleteMultipartUploads',
          abortIncompleteMultipartUploadAfter: cdk.Duration.days(1),
        },
      ],
      removalPolicy: environment === 'prod' ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });

    // Cognito User Pool
    this.userPool = new cognito.UserPool(this, 'UserPool', {
      userPoolName: `trade-manage-users-${environment}`,
      selfSignUpEnabled: true,
      signInAliases: {
        email: true,
        username: true,
      },
      autoVerify: {
        email: true,
      },
      standardAttributes: {
        email: {
          required: true,
          mutable: true,
        },
        givenName: {
          required: true,
          mutable: true,
        },
        familyName: {
          required: true,
          mutable: true,
        },
      },
      passwordPolicy: {
        minLength: 8,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: environment === 'prod' ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });

    // Cognito User Pool Client
    this.userPoolClient = new cognito.UserPoolClient(this, 'UserPoolClient', {
      userPool: this.userPool,
      userPoolClientName: `trade-manage-client-${environment}`,
      generateSecret: false,
      authFlows: {
        adminUserPassword: true,
        userPassword: true,
        userSrp: true,
      },
      oAuth: {
        flows: {
          authorizationCodeGrant: true,
        },
        scopes: [cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL, cognito.OAuthScope.PROFILE],
      },
    });

    // DynamoDB Tables
    this.usersTable = new dynamodb.Table(this, 'UsersTable', {
      tableName: `trade-manage-${environment}-users`,
      partitionKey: {
        name: 'userId',
        type: dynamodb.AttributeType.STRING,
      },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecovery: environment === 'prod',
      removalPolicy: environment === 'prod' ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });

    // Add GSI for email lookup
    this.usersTable.addGlobalSecondaryIndex({
      indexName: 'EmailIndex',
      partitionKey: {
        name: 'email',
        type: dynamodb.AttributeType.STRING,
      },
    });

    this.tradesTable = new dynamodb.Table(this, 'TradesTable', {
      tableName: `trade-manage-${environment}-trades`,
      partitionKey: {
        name: 'tradeId',
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: {
        name: 'createdAt',
        type: dynamodb.AttributeType.STRING,
      },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecovery: environment === 'prod',
      removalPolicy: environment === 'prod' ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });

    // Add GSI for user trades lookup
    this.tradesTable.addGlobalSecondaryIndex({
      indexName: 'UserTradesIndex',
      partitionKey: {
        name: 'userId',
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: {
        name: 'createdAt',
        type: dynamodb.AttributeType.STRING,
      },
    });

    this.filesTable = new dynamodb.Table(this, 'FilesTable', {
      tableName: `trade-manage-${environment}-files`,
      partitionKey: {
        name: 'fileId',
        type: dynamodb.AttributeType.STRING,
      },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecovery: environment === 'prod',
      removalPolicy: environment === 'prod' ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });

    // Add GSI for user files lookup
    this.filesTable.addGlobalSecondaryIndex({
      indexName: 'UserFilesIndex',
      partitionKey: {
        name: 'userId',
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: {
        name: 'uploadedAt',
        type: dynamodb.AttributeType.STRING,
      },
    });

    // Customers Table - 客户信息表
    this.customersTable = new dynamodb.Table(this, 'CustomersTable', {
      tableName: `trade-manage-${environment}-customers`,
      partitionKey: {
        name: 'customerId',
        type: dynamodb.AttributeType.STRING,
      },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecovery: environment === 'prod',
      removalPolicy: environment === 'prod' ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });

    // Add GSI for email lookup
    this.customersTable.addGlobalSecondaryIndex({
      indexName: 'EmailIndex',
      partitionKey: {
        name: 'email',
        type: dynamodb.AttributeType.STRING,
      },
    });

    // Add GSI for phone lookup
    this.customersTable.addGlobalSecondaryIndex({
      indexName: 'PhoneIndex',
      partitionKey: {
        name: 'phone',
        type: dynamodb.AttributeType.STRING,
      },
    });

    // Products Table - 产品信息表
    this.productsTable = new dynamodb.Table(this, 'ProductsTable', {
      tableName: `trade-manage-${environment}-products`,
      partitionKey: {
        name: 'productId',
        type: dynamodb.AttributeType.STRING,
      },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecovery: environment === 'prod',
      removalPolicy: environment === 'prod' ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });

    // Add GSI for product type lookup
    this.productsTable.addGlobalSecondaryIndex({
      indexName: 'ProductTypeIndex',
      partitionKey: {
        name: 'productType',
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: {
        name: 'createdAt',
        type: dynamodb.AttributeType.STRING,
      },
    });

    // Add GSI for status lookup
    this.productsTable.addGlobalSecondaryIndex({
      indexName: 'StatusIndex',
      partitionKey: {
        name: 'status',
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: {
        name: 'createdAt',
        type: dynamodb.AttributeType.STRING,
      },
    });

    // Customer Product Transactions Table - 客户产品购买记录表
    this.customerProductTransactionsTable = new dynamodb.Table(this, 'CustomerProductTransactionsTable', {
      tableName: `trade-manage-${environment}-customer-product-transactions`,
      partitionKey: {
        name: 'transactionId',
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: {
        name: 'createdAt',
        type: dynamodb.AttributeType.STRING,
      },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecovery: environment === 'prod',
      removalPolicy: environment === 'prod' ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });

    // Add GSI for customer transactions lookup
    this.customerProductTransactionsTable.addGlobalSecondaryIndex({
      indexName: 'CustomerTransactionsIndex',
      partitionKey: {
        name: 'customerId',
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: {
        name: 'createdAt',
        type: dynamodb.AttributeType.STRING,
      },
    });

    // Add GSI for product transactions lookup
    this.customerProductTransactionsTable.addGlobalSecondaryIndex({
      indexName: 'ProductTransactionsIndex',
      partitionKey: {
        name: 'productId',
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: {
        name: 'createdAt',
        type: dynamodb.AttributeType.STRING,
      },
    });

    // Add GSI for transaction status lookup
    this.customerProductTransactionsTable.addGlobalSecondaryIndex({
      indexName: 'TransactionStatusIndex',
      partitionKey: {
        name: 'transactionStatus',
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: {
        name: 'createdAt',
        type: dynamodb.AttributeType.STRING,
      },
    });

    // Lambda Function for API
    this.apiLambda = new lambda.Function(this, 'ApiLambda', {
      functionName: `trade-manage-api-${environment}`,
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'lambda.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../../lambda-package')),
      timeout: cdk.Duration.seconds(30),
      memorySize: 512,
      environment: {
        // Application Configuration
        NODE_ENV: environment === 'prod' ? 'production' : 'development',
        SWAGGER_ENABLED: environment === 'prod' ? 'false' : 'true',
        PORT: '3000',
        APP_NAME: 'trade-manage-backend',

        // AWS Configuration (AWS_REGION is automatically set by Lambda runtime)
        APP_AWS_REGION: this.region,

        // AWS S3 Configuration
        S3_BUCKET_NAME: this.s3Bucket.bucketName,
        S3_IMPORT_EXPORT_BUCKET_NAME: this.importExportBucket.bucketName,
        S3_REGION: this.region,

        // AWS Cognito Configuration
        COGNITO_USER_POOL_ID: this.userPool.userPoolId,
        COGNITO_CLIENT_ID: this.userPoolClient.userPoolClientId,
        COGNITO_REGION: this.region,

        // AWS DynamoDB Configuration
        DYNAMODB_REGION: this.region,
        DYNAMODB_TABLE_PREFIX: `trade-manage-${environment}`,

        // JWT Configuration
        JWT_SECRET: environment === 'prod' ? 'CHANGE_THIS_IN_PRODUCTION' : 'dev-secret-key',
        JWT_EXPIRES_IN: '24h',

        // Database Configuration
        DB_TABLE_USERS: this.usersTable.tableName,
        DB_TABLE_TRADES: this.tradesTable.tableName,
        DB_TABLE_FILES: this.filesTable.tableName,
        DB_TABLE_CUSTOMERS: this.customersTable.tableName,
        DB_TABLE_PRODUCTS: this.productsTable.tableName,
        DB_TABLE_CUSTOMER_PRODUCT_TRANSACTIONS: this.customerProductTransactionsTable.tableName,

        // API Configuration
        API_PREFIX: 'api/v1',
        SWAGGER_TITLE: 'Trade Management API',
        SWAGGER_DESCRIPTION: 'API for Trade Management System',
        SWAGGER_VERSION: '1.0.0',
      },
    });

    // Grant permissions to Lambda
    this.s3Bucket.grantReadWrite(this.apiLambda);
    this.importExportBucket.grantReadWrite(this.apiLambda);
    this.usersTable.grantReadWriteData(this.apiLambda);
    this.tradesTable.grantReadWriteData(this.apiLambda);
    this.filesTable.grantReadWriteData(this.apiLambda);
    this.customersTable.grantReadWriteData(this.apiLambda);
    this.productsTable.grantReadWriteData(this.apiLambda);
    this.customerProductTransactionsTable.grantReadWriteData(this.apiLambda);

    // Grant Cognito permissions
    this.apiLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
          'cognito-idp:AdminCreateUser',
          'cognito-idp:AdminDeleteUser',
          'cognito-idp:AdminGetUser',
          'cognito-idp:AdminListGroupsForUser',
          'cognito-idp:AdminSetUserPassword',
          'cognito-idp:AdminUpdateUserAttributes',
          'cognito-idp:ListUsers',
          'cognito-idp:SignUp',
          'cognito-idp:ConfirmSignUp',
        ],
        resources: [this.userPool.userPoolArn],
      }),
    );

    // API Gateway
    this.api = new apigateway.RestApi(this, 'Api', {
      restApiName: `trade-manage-api-${environment}`,
      description: `Trade Management API - ${environment}`,
      deployOptions: {
        stageName: environment,
        description: `${environment} stage for Trade Management API`,
      },
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS,
        allowMethods: apigateway.Cors.ALL_METHODS,
        allowHeaders: [
          'Content-Type',
          'X-Amz-Date',
          'Authorization',
          'X-Api-Key',
          'X-Amz-Security-Token',
        ],
      },
    });

    // Lambda integration
    const lambdaIntegration = new apigateway.LambdaIntegration(this.apiLambda, {
      requestTemplates: { 'application/json': '{ "statusCode": "200" }' },
    });

    // Add proxy resource to handle all routes
    this.api.root.addProxy({
      defaultIntegration: lambdaIntegration,
      anyMethod: true,
    });

    // Create .env file content
    const envContent = [
      `# Application Configuration`,
      `NODE_ENV=${environment === 'prod' ? 'production' : 'development'}`,
      `PORT=3000`,
      `APP_NAME=trade-manage-backend`,
      ``,
      `# AWS Configuration`,
      `AWS_REGION=${this.region}`,
      ``,
      `# AWS S3 Configuration`,
      `S3_BUCKET_NAME=${this.s3Bucket.bucketName}`,
      `S3_IMPORT_EXPORT_BUCKET_NAME=${this.importExportBucket.bucketName}`,
      `S3_REGION=${this.region}`,
      ``,
      `# AWS Cognito Configuration`,
      `COGNITO_USER_POOL_ID=${this.userPool.userPoolId}`,
      `COGNITO_CLIENT_ID=${this.userPoolClient.userPoolClientId}`,
      `COGNITO_REGION=${this.region}`,
      ``,
      `# AWS DynamoDB Configuration`,
      `DYNAMODB_REGION=${this.region}`,
      `DYNAMODB_TABLE_PREFIX=trade-manage-${environment}`,
      ``,
      `# JWT Configuration`,
      `JWT_SECRET=${environment === 'prod' ? 'CHANGE_THIS_IN_PRODUCTION' : 'dev-secret-key'}`,
      `JWT_EXPIRES_IN=24h`,
      ``,
      `# Database Configuration`,
      `DB_TABLE_USERS=${this.usersTable.tableName}`,
      `DB_TABLE_TRADES=${this.tradesTable.tableName}`,
      `DB_TABLE_FILES=${this.filesTable.tableName}`,
      `DB_TABLE_CUSTOMERS=${this.customersTable.tableName}`,
      `DB_TABLE_PRODUCTS=${this.productsTable.tableName}`,
      `DB_TABLE_CUSTOMER_PRODUCT_TRANSACTIONS=${this.customerProductTransactionsTable.tableName}`,
      ``,
      `# API Configuration`,
      `API_PREFIX=api/v1`,
      `SWAGGER_ENABLED=${environment === 'prod' ? 'false' : 'true'}`,
      `SWAGGER_TITLE=Trade Management API`,
      `SWAGGER_DESCRIPTION=API for Trade Management System`,
      `SWAGGER_VERSION=1.0.0`,
      ``,
      `# Deployment Information (for reference)`,
      `API_GATEWAY_URL=${this.api.url}`,
      `API_GATEWAY_ID=${this.api.restApiId}`,
      `API_LAMBDA_FUNCTION_NAME=${this.apiLambda.functionName}`,
    ].join('\n');

    // Output API endpoint for quick reference
    new cdk.CfnOutput(this, 'ApiEndpoint', {
      value: this.api.url,
      description: 'API Gateway endpoint URL',
    });

    // Output .env file content with clear instructions
    new cdk.CfnOutput(this, 'EnvFileContent', {
      value: `
=== COPY THE CONTENT BELOW TO YOUR .env FILE ===

${envContent}

=== END OF .env FILE CONTENT ===

NOTES:
- AWS credentials are handled automatically by AWS SDK
- In Lambda: Uses IAM roles (no credentials needed)
- Local development: Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY as environment variables
- Never commit AWS credentials to code!
`,
      description: 'Ready-to-use .env file content - copy everything between the === markers',
    });
  }
}
