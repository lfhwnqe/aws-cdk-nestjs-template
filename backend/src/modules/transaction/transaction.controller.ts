import {
  Controller,
  Get,
  Post,
  Body,
  Put,
  Param,
  Delete,
  Query,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  BadRequestException,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiConsumes,
} from '@nestjs/swagger';

import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles, Role } from '../../common/decorators/roles.decorator';

import { TransactionService } from './transaction.service';
import { CreateTransactionDto } from './dto/create-transaction.dto';
import { UpdateTransactionDto } from './dto/update-transaction.dto';
import {
  QueryTransactionDto,
  TransactionListResponse,
} from './dto/query-transaction.dto';
import { ImportResultDto } from './dto/import-result.dto';
import { Transaction } from './entities/transaction.entity';
import { ExportService } from '../import-export/export.service';
import { ImportService } from '../import-export/import.service';
import { TriggerImportDto } from '@/modules/import-export/dto/trigger-import.dto';

@ApiTags('Transactions')
@ApiBearerAuth('JWT-auth')
@UseGuards(RolesGuard)
@Controller('transactions')
export class TransactionController {
  constructor(
    private readonly service: TransactionService,
    private readonly exportService: ExportService,
    private readonly importService: ImportService,
  ) {}

  @Post()
  @Roles(Role.SUPER_ADMIN, Role.ADMIN)
  @ApiOperation({ summary: '创建交易记录' })
  create(@Body() dto: CreateTransactionDto): Promise<Transaction> {
    return this.service.create(dto);
  }

  @Get()
  @Roles(Role.SUPER_ADMIN, Role.ADMIN, Role.USER)
  @ApiOperation({ summary: '获取交易记录列表' })
  findAll(
    @Query() query: QueryTransactionDto,
  ): Promise<TransactionListResponse> {
    return this.service.findAll(query);
  }

  @Get('export')
  @Roles(Role.SUPER_ADMIN, Role.ADMIN)
  @ApiOperation({ summary: '导出交易记录（返回S3短时效下载URL）' })
  async export() {
    const items = await this.service.getAllForExport();
    const buf = await this.service.generateExcelBuffer(items);
    const filename = `transactions_${new Date().toISOString().split('T')[0]}.xlsx`;

    const result = await this.exportService.uploadExcelAndGetUrl({
      buffer: buf,
      fileName: filename,
      prefix: 'exports/transactions',
      expiresInSeconds: 600,
      metadata: { module: 'transactions' },
    });

    return {
      downloadUrl: result.url,
      expireAt: result.expiresAt.toISOString(),
      fileName: filename,
      objectKey: result.key,
      bucket: result.bucket,
      size: buf.length,
    };
  }

  @Get(':id')
  @Roles(Role.SUPER_ADMIN, Role.ADMIN, Role.USER)
  @ApiOperation({ summary: '获取交易记录详情' })
  @ApiParam({ name: 'id', description: '交易ID' })
  findOne(@Param('id') id: string): Promise<Transaction> {
    return this.service.findOne(id);
  }

  @Put(':id')
  @Roles(Role.SUPER_ADMIN, Role.ADMIN)
  @ApiOperation({ summary: '更新交易记录' })
  @ApiParam({ name: 'id', description: '交易ID' })
  update(
    @Param('id') id: string,
    @Body() dto: UpdateTransactionDto,
  ): Promise<Transaction> {
    return this.service.update(id, dto);
  }

  @Delete(':id')
  @Roles(Role.SUPER_ADMIN, Role.ADMIN)
  @ApiOperation({ summary: '删除交易记录' })
  @ApiParam({ name: 'id', description: '交易ID' })
  remove(@Param('id') id: string) {
    return this.service.remove(id);
  }

  @Post('import')
  @Roles(Role.SUPER_ADMIN, Role.ADMIN)
  @UseInterceptors(FileInterceptor('file'))
  @ApiConsumes('multipart/form-data')
  @ApiOperation({ summary: '从Excel导入交易记录' })
  async import(
    @UploadedFile() file: Express.Multer.File,
  ): Promise<ImportResultDto> {
    if (!file) throw new BadRequestException('请选择要上传的Excel文件');
    return this.service.importFromExcel(file);
  }

  @Post('imports/s3')
  @Roles(Role.SUPER_ADMIN, Role.ADMIN)
  @ApiOperation({ summary: '从S3拉取Excel（key），解析并导入交易记录' })
  async importFromS3(@Body() dto: TriggerImportDto): Promise<ImportResultDto> {
    const { buffer, contentType } = await this.importService.getObjectBuffer(
      dto.key,
    );

    const inferred = dto.key.toLowerCase().endsWith('.xlsx')
      ? 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
      : dto.key.toLowerCase().endsWith('.xls')
        ? 'application/vnd.ms-excel'
        : undefined;

    const file: Express.Multer.File = {
      fieldname: 'file',
      originalname: dto.key.split('/').pop() || 'import.xlsx',
      encoding: '7bit',
      mimetype: contentType || inferred || 'application/octet-stream',
      size: buffer.length,
      buffer,
      destination: '',
      filename: '',
      path: '',
      stream: undefined as any,
    };

    return this.service.importFromExcel(file);
  }
}
