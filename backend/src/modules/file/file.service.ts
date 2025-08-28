import {
  Injectable,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { S3Service } from '../../shared/services/s3.service';
import { DynamodbService } from '../../database/dynamodb.service';

@Injectable()
export class FileService {
  constructor(
    private s3Service: S3Service,
    private dynamodbService: DynamodbService,
  ) {}

  async uploadFile(
    userId: string,
    file: Express.Multer.File,
    description?: string,
  ) {
    const fileId = uuidv4();
    const now = new Date().toISOString();

    // Upload to S3
    const s3Key = await this.s3Service.uploadFile(
      file.buffer,
      file.originalname,
      file.mimetype,
    );

    // Save metadata to DynamoDB
    const fileMetadata = {
      fileId,
      userId,
      originalName: file.originalname,
      s3Key,
      mimeType: file.mimetype,
      size: file.size,
      description: description || '',
      uploadedAt: now,
      updatedAt: now,
    };

    await this.dynamodbService.put('files', fileMetadata);

    return fileMetadata;
  }

  async getPresignedUploadUrl(
    userId: string,
    fileName: string,
    contentType: string,
  ) {
    const { uploadUrl, key } = await this.s3Service.getPresignedUploadUrl(
      fileName,
      contentType,
    );

    // Pre-create file metadata
    const fileId = uuidv4();
    const now = new Date().toISOString();

    const fileMetadata = {
      fileId,
      userId,
      originalName: fileName,
      s3Key: key,
      mimeType: contentType,
      size: 0, // Will be updated after upload
      status: 'pending',
      uploadedAt: now,
      updatedAt: now,
    };

    await this.dynamodbService.put('files', fileMetadata);

    return {
      fileId,
      uploadUrl,
      key,
    };
  }

  async confirmUpload(fileId: string, userId: string, size: number) {
    const file = await this.dynamodbService.get('files', { fileId });

    if (!file) {
      throw new NotFoundException('File not found');
    }

    if (file.userId !== userId) {
      throw new ForbiddenException('Access denied');
    }

    return await this.dynamodbService.update(
      'files',
      { fileId },
      'SET #status = :status, #size = :size, #updatedAt = :updatedAt',
      {
        ':status': 'completed',
        ':size': size,
        ':updatedAt': new Date().toISOString(),
      },
      {
        '#status': 'status',
        '#size': 'size',
        '#updatedAt': 'updatedAt',
      },
    );
  }

  async findAll(userId?: string) {
    if (userId) {
      return await this.dynamodbService.query(
        'files',
        'userId = :userId',
        { ':userId': userId },
        'UserFilesIndex',
      );
    }
    return await this.dynamodbService.scan('files');
  }

  async findOne(fileId: string, userId?: string) {
    const file = await this.dynamodbService.get('files', { fileId });

    if (!file) {
      throw new NotFoundException('File not found');
    }

    if (userId && file.userId !== userId) {
      throw new ForbiddenException('Access denied');
    }

    return file;
  }

  async getFileUrl(fileId: string, userId?: string, expiresIn: number = 3600) {
    const file = await this.findOne(fileId, userId);
    const url = await this.s3Service.getFileUrl(file.s3Key, expiresIn);

    return {
      fileId,
      originalName: file.originalName,
      url,
      expiresIn,
    };
  }

  async remove(fileId: string, userId: string) {
    const file = await this.findOne(fileId, userId);

    // Delete from S3
    await this.s3Service.deleteFile(file.s3Key);

    // Delete from DynamoDB
    await this.dynamodbService.delete('files', { fileId });

    return { message: 'File deleted successfully' };
  }

  async getUserFiles(userId: string) {
    return await this.dynamodbService.query(
      'files',
      'userId = :userId',
      { ':userId': userId },
      'UserFilesIndex',
    );
  }
}
