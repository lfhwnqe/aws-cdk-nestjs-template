import { Injectable, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  GetObjectCommand,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class ImportService {
  private readonly s3: S3Client;
  private readonly bucket: string;

  constructor(private readonly configService: ConfigService) {
    const region =
      this.configService.get<string>('s3.region') ||
      this.configService.get<string>('aws.region');

    this.bucket =
      this.configService.get<string>('s3.importExportBucketName') || '';

    this.s3 = new S3Client({ region });
  }

  async getPresignedUploadUrl(params: {
    fileName: string;
    contentType: string;
    type: 'customer' | 'product' | 'transaction';
    expiresInSeconds?: number;
  }): Promise<{ uploadUrl: string; key: string; expiresIn: number }> {
    if (!this.bucket) {
      throw new BadRequestException(
        'S3 import/export bucket is not configured',
      );
    }

    const { fileName, contentType, type, expiresInSeconds = 600 } = params;

    const safeName = fileName.replace(/[^\w\-.\u4e00-\u9fa5]/g, '_');
    const key = `imports/${type}/${uuidv4()}-${safeName}`;

    const put = new PutObjectCommand({
      Bucket: this.bucket,
      Key: key,
      ContentType: contentType,
      Metadata: { originalFileName: fileName, importType: type },
    });

    const uploadUrl = await getSignedUrl(this.s3, put, {
      expiresIn: expiresInSeconds,
    });

    return { uploadUrl, key, expiresIn: expiresInSeconds };
  }

  async getObjectBuffer(
    key: string,
  ): Promise<{ buffer: Buffer; contentType?: string }> {
    if (!this.bucket) {
      throw new BadRequestException(
        'S3 import/export bucket is not configured',
      );
    }
    if (!key) {
      throw new BadRequestException('Invalid S3 object key');
    }

    const resp = await this.s3.send(
      new GetObjectCommand({ Bucket: this.bucket, Key: key }),
    );

    // resp.Body is a stream; collect to buffer
    const chunks: Buffer[] = [];
    await new Promise<void>((resolve, reject) => {
      (resp.Body as any)
        .on('data', (chunk: Buffer) => chunks.push(chunk))
        .on('error', reject)
        .on('end', () => resolve());
    });

    return { buffer: Buffer.concat(chunks), contentType: resp.ContentType };
  }
}
