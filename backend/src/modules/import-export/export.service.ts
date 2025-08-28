import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { v4 as uuidv4 } from 'uuid';

export interface UploadExcelInput {
  buffer: Buffer;
  fileName: string;
  contentType?: string;
  prefix?: string; // e.g. 'exports/customers'
  expiresInSeconds?: number; // presigned url ttl
  metadata?: Record<string, string>;
}

export interface UploadExcelResult {
  bucket: string;
  key: string;
  url: string;
  expiresAt: Date;
}

@Injectable()
export class ExportService {
  private readonly s3: S3Client;
  private readonly bucket: string;

  constructor(private readonly configService: ConfigService) {
    const region =
      this.configService.get<string>('s3.region') ||
      this.configService.get<string>('aws.region');

    this.bucket =
      this.configService.get<string>('s3.importExportBucketName') ||
      process.env.S3_IMPORT_EXPORT_BUCKET_NAME ||
      '';

    this.s3 = new S3Client({ region });
  }

  // 接收 Excel Buffer，上传到 S3，并返回短时效下载地址
  async uploadExcelAndGetUrl(
    input: UploadExcelInput,
  ): Promise<UploadExcelResult> {
    if (!this.bucket) {
      throw new Error('S3 import/export bucket is not configured');
    }

    const {
      buffer,
      fileName,
      contentType = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      prefix = 'exports',
      expiresInSeconds = 600, // 10 分钟
      metadata = {},
    } = input;

    const safeName = fileName.replace(/[^\w\-.\u4e00-\u9fa5]/g, '_');
    const key = `${prefix}/${uuidv4()}-${safeName}`;

    // Content-Disposition 设为附件下载并保留原始文件名
    const contentDisposition = `attachment; filename="${safeName}"`;

    const put = new PutObjectCommand({
      Bucket: this.bucket,
      Key: key,
      Body: buffer,
      ContentType: contentType,
      ContentDisposition: contentDisposition,
      Metadata: {
        originalFileName: fileName,
        ...metadata,
      },
    });

    await this.s3.send(put);

    const get = new GetObjectCommand({ Bucket: this.bucket, Key: key });
    const url = await getSignedUrl(this.s3, get, {
      expiresIn: expiresInSeconds,
    });

    return {
      bucket: this.bucket,
      key,
      url,
      expiresAt: new Date(Date.now() + expiresInSeconds * 1000),
    };
  }
}
