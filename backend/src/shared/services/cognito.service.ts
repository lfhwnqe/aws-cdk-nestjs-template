import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  CognitoIdentityProviderClient,
  AdminCreateUserCommand,
  AdminSetUserPasswordCommand,
  AdminGetUserCommand,
  AdminUpdateUserAttributesCommand,
  AdminDeleteUserCommand,
  ListUsersCommand,
  ConfirmSignUpCommand,
  SignUpCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import crypto from 'node:crypto';

@Injectable()
export class CognitoService {
  private cognitoClient: CognitoIdentityProviderClient;
  private userPoolId: string;
  private clientId: string;
  private clientSecret?: string;

  constructor(private configService: ConfigService) {
    const region = this.configService.get<string>('cognito.region');

    // AWS SDK will automatically use:
    // - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY) for local development
    // - IAM roles when running in Lambda/EC2
    // - AWS CLI credentials as fallback
    this.cognitoClient = new CognitoIdentityProviderClient({
      region,
    });
    this.userPoolId = this.configService.get<string>('cognito.userPoolId');
    this.clientId = this.configService.get<string>('cognito.clientId');
    this.clientSecret = this.configService.get<string>('cognito.clientSecret');
  }

  private computeSecretHash(username: string): string | undefined {
    if (!this.clientSecret || !this.clientId) return undefined;
    const hmac = crypto.createHmac('sha256', this.clientSecret);
    hmac.update(username + this.clientId);
    return hmac.digest('base64');
  }

  async createUser(
    username: string,
    email: string,
    temporaryPassword: string,
  ): Promise<any> {
    const command = new AdminCreateUserCommand({
      UserPoolId: this.userPoolId,
      Username: username,
      UserAttributes: [
        {
          Name: 'email',
          Value: email,
        },
        {
          Name: 'email_verified',
          Value: 'true',
        },
      ],
      TemporaryPassword: temporaryPassword,
      MessageAction: 'SUPPRESS',
    });

    return await this.cognitoClient.send(command);
  }

  async setUserPassword(
    username: string,
    password: string,
    permanent: boolean = true,
  ): Promise<any> {
    const command = new AdminSetUserPasswordCommand({
      UserPoolId: this.userPoolId,
      Username: username,
      Password: password,
      Permanent: permanent,
    });

    return await this.cognitoClient.send(command);
  }

  async getUser(username: string): Promise<any> {
    const command = new AdminGetUserCommand({
      UserPoolId: this.userPoolId,
      Username: username,
    });

    return await this.cognitoClient.send(command);
  }

  async updateUserAttributes(
    username: string,
    attributes: { Name: string; Value: string }[],
  ): Promise<any> {
    const command = new AdminUpdateUserAttributesCommand({
      UserPoolId: this.userPoolId,
      Username: username,
      UserAttributes: attributes,
    });

    return await this.cognitoClient.send(command);
  }

  async deleteUser(username: string): Promise<any> {
    const command = new AdminDeleteUserCommand({
      UserPoolId: this.userPoolId,
      Username: username,
    });

    return await this.cognitoClient.send(command);
  }

  async listUsers(limit: number = 10, paginationToken?: string): Promise<any> {
    const command = new ListUsersCommand({
      UserPoolId: this.userPoolId,
      Limit: limit,
      PaginationToken: paginationToken,
    });

    return await this.cognitoClient.send(command);
  }

  async confirmSignUp(
    username: string,
    confirmationCode: string,
  ): Promise<any> {
    const secretHash = this.computeSecretHash(username);
    const command = new ConfirmSignUpCommand({
      ClientId: this.clientId,
      Username: username,
      ConfirmationCode: confirmationCode,
      ...(secretHash ? { SecretHash: secretHash } : {}),
    });

    return await this.cognitoClient.send(command);
  }

  async signUp(
    username: string,
    password: string,
    email: string,
    firstName: string,
    lastName: string,
  ): Promise<any> {
    const clientId = this.clientId;
    const secretHash = this.computeSecretHash(username);

    // 默认包含 email，另外尽力包含 given_name/family_name（若用户池未启用将回退）
    const baseAttributes = [{ Name: 'email', Value: email }];
    const withNameAttributes = [
      ...baseAttributes,
      { Name: 'given_name', Value: firstName },
      { Name: 'family_name', Value: lastName },
    ];

    try {
      // 这里不记录密码，仅输出传递的关键上下文
      // 使用 console.debug 避免污染 info 日志
      // eslint-disable-next-line no-console
      console.debug(
        `Cognito SignUp request => username=${username}, hasSecretHash=${!!secretHash}, attributes=${withNameAttributes
          .map((a) => a.Name)
          .join(',')}`,
      );
      const cmd = new SignUpCommand({
        ClientId: clientId,
        Username: username,
        Password: password,
        UserAttributes: withNameAttributes,
        ...(secretHash ? { SecretHash: secretHash } : {}),
      });
      return await this.cognitoClient.send(cmd);
    } catch (e) {
      const name = (e && ((e as any).name || (e as any).__type)) || '';
      // 如果 given_name/family_name 未在用户池中启用，回退仅携带 email 重新尝试
      if (name === 'InvalidParameterException') {
        // eslint-disable-next-line no-console
        console.debug(
          'Cognito SignUp fallback => retry with only base email attribute',
        );
        const fallbackCmd = new SignUpCommand({
          ClientId: clientId,
          Username: username,
          Password: password,
          UserAttributes: baseAttributes,
          ...(secretHash ? { SecretHash: secretHash } : {}),
        });
        return await this.cognitoClient.send(fallbackCmd);
      }
      throw e;
    }
  }
}
