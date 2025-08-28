import { BadRequestException, Body, Controller, Post } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { ImportService } from './import.service';
import { GetPresignedImportUrlDto } from './dto/get-presigned-import-url.dto';
// TriggerImportDto 与导入动作已迁移至 CustomerModule

@ApiTags('Import/Export')
@ApiBearerAuth('JWT-auth')
@Controller('import-export')
export class ImportController {
  constructor(private readonly importService: ImportService) {}

  @Post('imports/presigned-url')
  @ApiOperation({ summary: '获取导入文件的S3预签名上传URL' })
  @ApiBody({ type: GetPresignedImportUrlDto })
  @ApiResponse({ status: 201, description: '生成成功' })
  async getPresignedImportUrl(
    @Body() dto: GetPresignedImportUrlDto,
  ): Promise<{ uploadUrl: string; key: string; expiresIn: number }> {
    // 基础内容类型检查，进一步严格校验交给前端与后端导入时再验证
    if (!dto.fileName.match(/\.(xlsx|xls)$/i)) {
      throw new BadRequestException('仅支持Excel文件 (.xlsx 或 .xls)');
    }

    return this.importService.getPresignedUploadUrl({
      fileName: dto.fileName,
      contentType: dto.contentType,
      type: dto.type,
    });
  }
}
