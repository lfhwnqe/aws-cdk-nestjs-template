import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class S3Service {
  private s3Client: S3Client;
  private bucketName: string;

  constructor(private configService: ConfigService) {
    const region = this.configService.get<string>('s3.region');

    // AWS SDK will automatically use:
    // - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY) for local development
    // - IAM roles when running in Lambda/EC2
    // - AWS CLI credentials as fallback
    this.s3Client = new S3Client({
      region,
    });
    this.bucketName = this.configService.get<string>('s3.bucketName');
  }

  async uploadFile(
    file: Buffer,
    fileName: string,
    contentType: string,
  ): Promise<string> {
    const key = `${uuidv4()}-${fileName}`;

    const command = new PutObjectCommand({
      Bucket: this.bucketName,
      Key: key,
      Body: file,
      ContentType: contentType,
    });

    await this.s3Client.send(command);
    return key;
  }

  async getFileUrl(key: string, expiresIn: number = 3600): Promise<string> {
    const command = new GetObjectCommand({
      Bucket: this.bucketName,
      Key: key,
    });

    return await getSignedUrl(this.s3Client, command, { expiresIn });
  }

  async deleteFile(key: string): Promise<void> {
    const command = new DeleteObjectCommand({
      Bucket: this.bucketName,
      Key: key,
    });

    await this.s3Client.send(command);
  }

  async getPresignedUploadUrl(
    fileName: string,
    contentType: string,
    expiresIn: number = 3600,
  ): Promise<{ uploadUrl: string; key: string }> {
    const key = `${uuidv4()}-${fileName}`;

    const command = new PutObjectCommand({
      Bucket: this.bucketName,
      Key: key,
      ContentType: contentType,
    });

    const uploadUrl = await getSignedUrl(this.s3Client, command, { expiresIn });

    return { uploadUrl, key };
  }
}
