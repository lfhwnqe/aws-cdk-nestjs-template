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
  ApiBody,
} from '@nestjs/swagger';

import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles, Role } from '../../common/decorators/roles.decorator';

import { ProductService } from './product.service';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import { QueryProductDto, ProductListResponse } from './dto/query-product.dto';
import { ImportResultDto } from './dto/import-result.dto';
import { Product } from './entities/product.entity';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { ExportService } from '../import-export/export.service';
import { ImportService } from '../import-export/import.service';
import { TriggerImportDto } from '@/modules/import-export/dto/trigger-import.dto';

@ApiTags('Products')
@ApiBearerAuth('JWT-auth')
@UseGuards(RolesGuard)
@Controller('products')
export class ProductController {
  constructor(
    private readonly productService: ProductService,
    private readonly exportService: ExportService,
    private readonly importService: ImportService,
  ) {}

  @Post()
  @Roles(Role.SUPER_ADMIN, Role.ADMIN)
  @ApiOperation({ summary: '创建产品' })
  create(
    @Body() dto: CreateProductDto,
    @CurrentUser() user: any,
  ): Promise<Product> {
    return this.productService.create(dto, user.userId);
  }

  @Get()
  @Roles(Role.SUPER_ADMIN, Role.ADMIN, Role.USER)
  @ApiOperation({ summary: '获取产品列表' })
  @ApiQuery({ name: 'page', required: false })
  findAll(
    @Query() query: QueryProductDto,
    @CurrentUser() user: any,
  ): Promise<ProductListResponse> {
    return this.productService.findAll(query, {
      userId: user.userId,
      role: user.role,
    });
  }

  @Get('export')
  @Roles(Role.SUPER_ADMIN, Role.ADMIN)
  @ApiOperation({ summary: '导出产品数据（返回S3短时效下载URL）' })
  async export(@CurrentUser() user: any) {
    const products = await this.productService.getAllForExport({
      userId: user.userId,
      role: user.role,
    });
    const buf = await this.productService.generateExcelBuffer(products);
    const filename = `products_${new Date().toISOString().split('T')[0]}.xlsx`;

    const result = await this.exportService.uploadExcelAndGetUrl({
      buffer: buf,
      fileName: filename,
      prefix: 'exports/products',
      expiresInSeconds: 600,
      metadata: { module: 'products', requestedBy: user.userId },
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
  @ApiOperation({ summary: '获取产品详情' })
  @ApiParam({ name: 'id', description: '产品ID' })
  findOne(@Param('id') id: string, @CurrentUser() user: any): Promise<Product> {
    return this.productService.findOne(id, {
      userId: user.userId,
      role: user.role,
    });
  }

  @Put(':id')
  @Roles(Role.SUPER_ADMIN, Role.ADMIN)
  @ApiOperation({ summary: '更新产品' })
  @ApiParam({ name: 'id', description: '产品ID' })
  // 明确声明请求体以改善 Swagger 展示
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  @ApiBody({ type: UpdateProductDto, description: '可更新字段' })
  update(
    @Param('id') id: string,
    @Body() dto: UpdateProductDto,
    @CurrentUser() user: any,
  ): Promise<Product> {
    return this.productService.update(id, dto, {
      userId: user.userId,
      role: user.role,
    });
  }

  @Delete(':id')
  @Roles(Role.SUPER_ADMIN, Role.ADMIN)
  @ApiOperation({ summary: '删除产品' })
  @ApiParam({ name: 'id', description: '产品ID' })
  remove(@Param('id') id: string, @CurrentUser() user: any) {
    return this.productService.remove(id, {
      userId: user.userId,
      role: user.role,
    });
  }

  @Post('import')
  @Roles(Role.SUPER_ADMIN, Role.ADMIN)
  @UseInterceptors(FileInterceptor('file'))
  @ApiConsumes('multipart/form-data')
  @ApiOperation({ summary: '从Excel导入产品数据' })
  async import(
    @UploadedFile() file: Express.Multer.File,
    @CurrentUser() user: any,
  ): Promise<ImportResultDto> {
    if (!file) throw new BadRequestException('请选择要上传的Excel文件');
    return this.productService.importFromExcel(file, user.userId);
  }

  @Post('imports/s3')
  @Roles(Role.SUPER_ADMIN, Role.ADMIN)
  @ApiOperation({ summary: '从S3拉取Excel（key），解析并导入产品数据' })
  async importFromS3(
    @Body() dto: TriggerImportDto,
    @CurrentUser('userId') userId: string,
  ): Promise<ImportResultDto> {
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

    return this.productService.importFromExcel(file, userId);
  }
}
