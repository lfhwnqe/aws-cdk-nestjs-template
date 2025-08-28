import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Delete,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  Query,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiParam,
  ApiConsumes,
  ApiBody,
  ApiQuery,
} from '@nestjs/swagger';

import { FileService } from './file.service';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Roles, Role } from '../../common/decorators/roles.decorator';
import { UploadFileDto } from './dto/upload-file.dto';
import { GetPresignedUrlDto } from './dto/get-presigned-url.dto';
import { ConfirmUploadDto } from './dto/confirm-upload.dto';

@ApiTags('Files')
@Controller('files')
@ApiBearerAuth('JWT-auth')
export class FileController {
  constructor(private readonly fileService: FileService) {}

  @Post('upload')
  @UseInterceptors(FileInterceptor('file'))
  @ApiOperation({ summary: 'Upload a file directly' })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    description: 'File upload',
    type: UploadFileDto,
  })
  @ApiResponse({ status: 201, description: 'File uploaded successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  uploadFile(
    @CurrentUser('userId') userId: string,
    @UploadedFile() file: Express.Multer.File,
    @Body('description') description?: string,
  ) {
    return this.fileService.uploadFile(userId, file, description);
  }

  @Post('presigned-url')
  @ApiOperation({ summary: 'Get presigned URL for file upload' })
  @ApiResponse({
    status: 201,
    description: 'Presigned URL generated successfully',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getPresignedUrl(
    @CurrentUser('userId') userId: string,
    @Body() getPresignedUrlDto: GetPresignedUrlDto,
  ) {
    return this.fileService.getPresignedUploadUrl(
      userId,
      getPresignedUrlDto.fileName,
      getPresignedUrlDto.contentType,
    );
  }

  @Post(':id/confirm')
  @ApiOperation({ summary: 'Confirm file upload completion' })
  @ApiParam({ name: 'id', description: 'File ID' })
  @ApiResponse({ status: 200, description: 'Upload confirmed successfully' })
  @ApiResponse({ status: 404, description: 'File not found' })
  confirmUpload(
    @Param('id') id: string,
    @CurrentUser('userId') userId: string,
    @Body() confirmUploadDto: ConfirmUploadDto,
  ) {
    return this.fileService.confirmUpload(id, userId, confirmUploadDto.size);
  }

  @Get()
  @ApiOperation({ summary: 'Get all files' })
  @ApiQuery({
    name: 'userId',
    required: false,
    description: 'Filter by user ID',
  })
  @ApiResponse({ status: 200, description: 'Files retrieved successfully' })
  findAll(@CurrentUser() user: any, @Query('userId') userId?: string) {
    // Regular users can only see their own files
    if (user.role !== 'super_admin') {
      return this.fileService.findAll(user.userId);
    }

    // Admins can see all files or filter by userId
    return this.fileService.findAll(userId);
  }

  @Get('my-files')
  @ApiOperation({ summary: 'Get current user files' })
  @ApiResponse({
    status: 200,
    description: 'User files retrieved successfully',
  })
  getUserFiles(@CurrentUser('userId') userId: string) {
    return this.fileService.getUserFiles(userId);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get file metadata by ID' })
  @ApiParam({ name: 'id', description: 'File ID' })
  @ApiResponse({ status: 200, description: 'File retrieved successfully' })
  @ApiResponse({ status: 404, description: 'File not found' })
  @ApiResponse({ status: 403, description: 'Access denied' })
  findOne(@Param('id') id: string, @CurrentUser() user: any) {
    // Regular users can only access their own files
    const userId = user.role === 'super_admin' ? undefined : user.userId;
    return this.fileService.findOne(id, userId);
  }

  @Get(':id/download')
  @ApiOperation({ summary: 'Get file download URL' })
  @ApiParam({ name: 'id', description: 'File ID' })
  @ApiQuery({
    name: 'expiresIn',
    required: false,
    description: 'URL expiration time in seconds',
  })
  @ApiResponse({
    status: 200,
    description: 'Download URL generated successfully',
  })
  @ApiResponse({ status: 404, description: 'File not found' })
  @ApiResponse({ status: 403, description: 'Access denied' })
  getDownloadUrl(
    @Param('id') id: string,
    @CurrentUser() user: any,
    @Query('expiresIn') expiresIn?: number,
  ) {
    // Regular users can only access their own files
    const userId = user.role === 'super_admin' ? undefined : user.userId;
    return this.fileService.getFileUrl(id, userId, expiresIn);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete file by ID' })
  @ApiParam({ name: 'id', description: 'File ID' })
  @ApiResponse({ status: 200, description: 'File deleted successfully' })
  @ApiResponse({ status: 404, description: 'File not found' })
  @ApiResponse({ status: 403, description: 'Access denied' })
  remove(@Param('id') id: string, @CurrentUser('userId') userId: string) {
    return this.fileService.remove(id, userId);
  }
}
