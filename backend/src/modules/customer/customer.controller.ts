import {
  Controller,
  Get,
  Post,
  Body,
  Put,
  Param,
  Query,
  UseGuards,
  HttpStatus,
  Logger,
  UseInterceptors,
  UploadedFile,
  BadRequestException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiParam,
  ApiQuery,
  ApiConsumes,
} from '@nestjs/swagger';
import { FileInterceptor } from '@nestjs/platform-express';
import { CurrentUser } from '../../common/decorators/current-user.decorator';

import { CustomerService } from './customer.service';
import { CreateCustomerDto } from './dto/create-customer.dto';
import { UpdateCustomerDto } from './dto/update-customer.dto';
import {
  QueryCustomerDto,
  CustomerListResponse,
} from './dto/query-customer.dto';
import { ImportResultDto } from './dto/import-result.dto';
import { Customer } from './entities/customer.entity';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles, Role } from '../../common/decorators/roles.decorator';
import { ExportService } from '../import-export/export.service';
import { ImportService } from '../import-export/import.service';
import { TriggerImportDto } from '@/modules/import-export/dto/trigger-import.dto';

@ApiTags('Customers')
@Controller('customers')
@ApiBearerAuth('JWT-auth')
@UseGuards(RolesGuard)
export class CustomerController {
  private readonly logger = new Logger(CustomerController.name);

  constructor(
    private readonly customerService: CustomerService,
    private readonly exportService: ExportService,
    private readonly importService: ImportService,
  ) {}

  @Post()
  @Roles(Role.SUPER_ADMIN, Role.ADMIN, Role.USER)
  @ApiOperation({ summary: '创建新客户' })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: '客户创建成功',
    type: Customer,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: '请求参数错误',
  })
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: '邮箱或手机号已存在',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: '未授权',
  })
  async create(
    @Body() createCustomerDto: CreateCustomerDto,
    @CurrentUser('userId') userId: string,
  ): Promise<Customer> {
    this.logger.log(`Creating customer with email: ${createCustomerDto.email}`);
    return await this.customerService.create(createCustomerDto, userId);
  }

  @Get()
  @Roles(Role.SUPER_ADMIN, Role.ADMIN, Role.USER)
  @ApiOperation({ summary: '获取客户列表' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: '客户列表获取成功',
    type: CustomerListResponse,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: '请求参数错误',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: '未授权',
  })
  async findAll(
    @Query() queryDto: QueryCustomerDto,
    @CurrentUser() user: any,
  ): Promise<CustomerListResponse> {
    this.logger.log(
      `Querying customers with params: ${JSON.stringify(queryDto)}`,
    );
    return await this.customerService.findAll(queryDto, {
      userId: user.userId,
      role: user.role,
    });
  }

  @Get('search/email/:email')
  @Roles(Role.SUPER_ADMIN, Role.ADMIN, Role.USER)
  @ApiOperation({ summary: '根据邮箱查找客户' })
  @ApiParam({
    name: 'email',
    description: '客户邮箱',
    example: 'customer@example.com',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: '客户查找成功',
    type: Customer,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: '客户不存在',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: '未授权',
  })
  async findByEmail(
    @Param('email') email: string,
    @CurrentUser() user: any,
  ): Promise<Customer> {
    this.logger.log(`Finding customer by email: ${email}`);
    return await this.customerService.findByEmail(email, {
      userId: user.userId,
      role: user.role,
    });
  }

  @Get('search/phone/:phone')
  @Roles(Role.SUPER_ADMIN, Role.ADMIN, Role.USER)
  @ApiOperation({ summary: '根据手机号查找客户' })
  @ApiParam({
    name: 'phone',
    description: '客户手机号',
    example: '+86 138 0013 8000',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: '客户查找成功',
    type: Customer,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: '客户不存在',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: '未授权',
  })
  async findByPhone(
    @Param('phone') phone: string,
    @CurrentUser() user: any,
  ): Promise<Customer> {
    this.logger.log(`Finding customer by phone: ${phone}`);
    return await this.customerService.findByPhone(phone, {
      userId: user.userId,
      role: user.role,
    });
  }

  @Get('export')
  @Roles(Role.SUPER_ADMIN, Role.ADMIN, Role.USER)
  @ApiOperation({ summary: '导出客户数据（返回S3短时效下载URL）' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: '生成并上传Excel成功，返回下载URL',
    schema: {
      example: {
        downloadUrl: 'https://s3-presigned-url',
        expireAt: '2024-08-14T12:00:00.000Z',
        fileName: 'customers_2024-08-14.xlsx',
        objectKey: 'exports/customers/uuid-customers_2024-08-14.xlsx',
        bucket: 'trade-manage-import-export-dev-ap-southeast-1',
        size: 12345,
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: '导出失败',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: '未授权',
  })
  async exportCustomers(@CurrentUser() user: any): Promise<{
    downloadUrl: string;
    expireAt: string;
    fileName: string;
    objectKey: string;
    bucket: string;
    size: number;
  }> {
    this.logger.log('Exporting customers to Excel');

    try {
      // 获取所有客户数据
      const customers = await this.customerService.getAllCustomersForExport({
        userId: user.userId,
        role: user.role,
      });

      // 生成Excel文件
      const excelBuffer =
        await this.customerService.generateExcelBuffer(customers);

      const filename = `customers_${new Date().toISOString().split('T')[0]}.xlsx`;

      // 上传至S3并返回预签名下载URL
      const result = await this.exportService.uploadExcelAndGetUrl({
        buffer: excelBuffer,
        fileName: filename,
        prefix: `exports/customers`,
        expiresInSeconds: 600, // 10分钟
        metadata: {
          module: 'customers',
          requestedBy: user.userId,
        },
      });

      this.logger.log(
        `Excel exported to S3: key=${result.key}, bucket=${result.bucket}`,
      );

      return {
        downloadUrl: result.url,
        expireAt: result.expiresAt.toISOString(),
        fileName: filename,
        objectKey: result.key,
        bucket: result.bucket,
        size: excelBuffer.length,
      };
    } catch (error) {
      this.logger.error(
        `Failed to export customers: ${error.message}`,
        error.stack,
      );
      throw new BadRequestException(error.message || '导出客户数据失败');
    }
  }

  @Get(':id')
  @Roles(Role.SUPER_ADMIN, Role.ADMIN, Role.USER)
  @ApiOperation({ summary: '根据ID获取客户详情' })
  @ApiParam({
    name: 'id',
    description: '客户ID',
    example: 'cust_1234567890',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: '客户详情获取成功',
    type: Customer,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: '客户不存在',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: '未授权',
  })
  async findOne(
    @Param('id') id: string,
    @CurrentUser() user: any,
  ): Promise<Customer> {
    this.logger.log(`Finding customer by ID: ${id}`);
    return await this.customerService.findOne(id, {
      userId: user.userId,
      role: user.role,
    });
  }

  @Put(':id')
  @Roles(Role.SUPER_ADMIN, Role.ADMIN, Role.USER)
  @ApiOperation({ summary: '更新客户信息' })
  @ApiParam({
    name: 'id',
    description: '客户ID',
    example: 'cust_1234567890',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: '客户信息更新成功',
    type: Customer,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: '客户不存在',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: '请求参数错误',
  })
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: '邮箱或手机号已存在',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: '未授权',
  })
  async update(
    @Param('id') id: string,
    @Body() updateCustomerDto: UpdateCustomerDto,
    @CurrentUser() user: any,
  ): Promise<Customer> {
    this.logger.log(`Updating customer with ID: ${id}`);
    return await this.customerService.update(id, updateCustomerDto, {
      userId: user.userId,
      role: user.role,
    });
  }

  @Post('import')
  @Roles(Role.SUPER_ADMIN, Role.ADMIN, Role.USER)
  @UseInterceptors(FileInterceptor('file'))
  @ApiConsumes('multipart/form-data')
  @ApiOperation({ summary: '从Excel文件导入客户数据' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: '客户数据导入成功',
    type: ImportResultDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: '导入失败或文件格式错误',
  })
  @ApiResponse({
    status: HttpStatus.UNSUPPORTED_MEDIA_TYPE,
    description: '不支持的文件格式',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: '未授权',
  })
  async importCustomers(
    @UploadedFile() file: Express.Multer.File,
    @CurrentUser() user: any,
  ): Promise<ImportResultDto> {
    this.logger.log(
      `Importing customers from file: ${file?.originalname || 'unknown'}`,
    );

    if (!file) {
      throw new BadRequestException('请选择要上传的Excel文件');
    }

    return await this.customerService.importCustomersFromExcel(
      file,
      user.userId,
    );
  }

  @Post('imports/s3')
  @Roles(Role.SUPER_ADMIN, Role.ADMIN, Role.USER)
  @ApiOperation({ summary: '从S3拉取Excel（key），解析并导入客户数据' })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: '导入完成，返回统计结果',
  })
  async importCustomersFromS3(
    @Body() dto: TriggerImportDto,
    @CurrentUser('userId') userId: string,
  ) {
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

    return this.customerService.importCustomersFromExcel(file, userId);
  }
}
