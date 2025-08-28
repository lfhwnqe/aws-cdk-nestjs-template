import {
  Injectable,
  NotFoundException,
  ConflictException,
  BadRequestException,
  Logger,
  UnsupportedMediaTypeException,
  HttpException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { DynamodbService } from '../../database/dynamodb.service';
import { AuthService } from '../../auth/auth.service';
import { CreateCustomerDto } from './dto/create-customer.dto';
import { UpdateCustomerDto } from './dto/update-customer.dto';
import {
  QueryCustomerDto,
  CustomerListResponse,
} from './dto/query-customer.dto';
import {
  Customer,
  CustomerStatus,
  IdType,
  RiskLevel,
} from './entities/customer.entity';
import { ImportResultDto, ImportErrorDetail } from './dto/import-result.dto';
import { v4 as uuidv4 } from 'uuid';
import * as Excel from 'exceljs';

@Injectable()
export class CustomerService {
  private readonly logger = new Logger(CustomerService.name);
  private readonly tableName: string;

  constructor(
    private readonly dynamodbService: DynamodbService,
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
  ) {
    this.tableName = this.configService.get<string>(
      'database.tables.customers',
    );
  }

  /**
   * 创建新客户
   */
  async create(
    createCustomerDto: CreateCustomerDto,
    createdBy: string,
  ): Promise<Customer> {
    this.logger.log(
      `Creating new customer with email: ${createCustomerDto.email}`,
    );

    await this.checkEmailExists(createCustomerDto.email);
    await this.checkPhoneExists(createCustomerDto.phone);

    const now = new Date().toISOString();
    const customerId = `cust_${uuidv4()}`;

    const { username, password, ...rest } = createCustomerDto;

    const customer: Customer = {
      customerId,
      ...(rest as any),
      status: createCustomerDto.status || CustomerStatus.ACTIVE,
      createdAt: now,
      updatedAt: now,
      createdBy,
    };

    try {
      // 先创建登录账号（若提供了账号密码），再写入客户记录，避免脏数据
      if (username && password) {
        await this.authService.registerCustomerAccount(
          username,
          password,
          customer.email,
          customer.firstName,
          customer.lastName,
          customerId,
        );
      }

      await this.dynamodbService.put(this.tableName, customer);

      this.logger.log(`Customer created successfully with ID: ${customerId}`);
      return customer;
    } catch (error) {
      // 若账号已创建而客户落库失败，执行回滚
      if (username && password) {
        try {
          await this.authService.deleteCustomerAccount(username);
        } catch (_) {
          // 已在下层记录警告日志
        }
      }

      this.logger.error(
        `Failed to create customer: ${error.message}`,
        (error as any)?.stack,
      );
      // 透传已规范化的业务异常，否则统一为 400
      if (error instanceof HttpException) {
        throw error;
      }
      throw new BadRequestException('创建客户失败');
    }
  }

  /**
   * 获取客户列表（支持分页和筛选）
   */
  async findAll(
    queryDto: QueryCustomerDto,
    currentUser: { userId: string; role: string },
  ): Promise<CustomerListResponse> {
    this.logger.log(
      `Querying customers with filters: ${JSON.stringify(queryDto)}`,
    );

    try {
      // 构建筛选条件
      let filterExpression = '';
      const expressionAttributeValues: any = {};
      const expressionAttributeNames: any = {};

      // 状态筛选
      if (queryDto.status) {
        filterExpression += '#status = :status';
        expressionAttributeNames['#status'] = 'status';
        expressionAttributeValues[':status'] = queryDto.status;
      }

      // 风险等级筛选
      if (queryDto.riskLevel) {
        if (filterExpression) filterExpression += ' AND ';
        filterExpression += 'riskLevel = :riskLevel';
        expressionAttributeValues[':riskLevel'] = queryDto.riskLevel;
      }

      // 时间范围筛选
      if (queryDto.startDate) {
        if (filterExpression) filterExpression += ' AND ';
        filterExpression += 'createdAt >= :startDate';
        expressionAttributeValues[':startDate'] = queryDto.startDate;
      }

      if (queryDto.endDate) {
        if (filterExpression) filterExpression += ' AND ';
        filterExpression += 'createdAt <= :endDate';
        expressionAttributeValues[':endDate'] =
          queryDto.endDate + 'T23:59:59.999Z';
      }

      // 非超级管理员仅能查看自己创建的资源
      if ((currentUser?.role || 'user') !== 'super_admin') {
        if (filterExpression) filterExpression += ' AND ';
        filterExpression += '#createdBy = :createdBy';
        expressionAttributeNames['#createdBy'] = 'createdBy';
        expressionAttributeValues[':createdBy'] = currentUser.userId;
      }

      // 执行扫描查询
      const allItems = await this.dynamodbService.scan(
        this.tableName,
        filterExpression || undefined,
        Object.keys(expressionAttributeValues).length > 0
          ? expressionAttributeValues
          : undefined,
        Object.keys(expressionAttributeNames).length > 0
          ? expressionAttributeNames
          : undefined,
      );

      // 搜索关键词筛选（在内存中进行）
      let filteredItems = allItems;
      if (queryDto.search) {
        const searchTerm = queryDto.search.toLowerCase();
        filteredItems = allItems.filter((item) => {
          const fullName = `${item.firstName}${item.lastName}`.toLowerCase();
          return (
            fullName.includes(searchTerm) ||
            item.email.toLowerCase().includes(searchTerm) ||
            item.phone.includes(searchTerm)
          );
        });
      }

      // 排序
      filteredItems.sort((a, b) => {
        const aValue = a[queryDto.sortBy] || '';
        const bValue = b[queryDto.sortBy] || '';

        if (queryDto.sortOrder === 'asc') {
          return aValue.localeCompare(bValue);
        } else {
          return bValue.localeCompare(aValue);
        }
      });

      // 分页
      const total = filteredItems.length;
      const totalPages = Math.ceil(total / queryDto.limit);
      const startIndex = (queryDto.page - 1) * queryDto.limit;
      const endIndex = startIndex + queryDto.limit;
      const paginatedItems = filteredItems.slice(startIndex, endIndex);

      this.logger.log(
        `Found ${total} customers, returning page ${queryDto.page} with ${paginatedItems.length} items`,
      );

      return {
        data: paginatedItems,
        total,
        page: queryDto.page,
        limit: queryDto.limit,
        totalPages,
      };
    } catch (error) {
      this.logger.error(
        `Failed to query customers: ${error.message}`,
        error.stack,
      );
      throw new BadRequestException('查询客户列表失败');
    }
  }

  /**
   * 根据ID获取单个客户
   */
  async findOne(
    customerId: string,
    currentUser?: { userId: string; role: string },
  ): Promise<Customer> {
    this.logger.log(`Finding customer with ID: ${customerId}`);

    try {
      const customer = await this.dynamodbService.get(this.tableName, {
        customerId,
      });

      if (!customer) {
        this.logger.warn(`Customer not found with ID: ${customerId}`);
        throw new NotFoundException('客户不存在');
      }

      if (currentUser && currentUser.role !== 'super_admin') {
        if (customer.createdBy && customer.createdBy !== currentUser.userId) {
          this.logger.warn(`Customer not found with ID: ${customerId}`);
          throw new NotFoundException('客户不存在');
        }
      }

      this.logger.log(`Customer found: ${customerId}`);
      return customer;
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      this.logger.error(
        `Failed to find customer: ${error.message}`,
        error.stack,
      );
      throw new BadRequestException('查询客户失败');
    }
  }

  /**
   * 根据邮箱查找客户
   */
  async findByEmail(
    email: string,
    currentUser?: { userId: string; role: string },
  ): Promise<Customer> {
    this.logger.log(`Finding customer with email: ${email}`);

    try {
      const customers = await this.dynamodbService.query(
        this.tableName,
        'email = :email',
        { ':email': email },
        'EmailIndex',
      );

      if (customers.length === 0) {
        this.logger.warn(`Customer not found with email: ${email}`);
        throw new NotFoundException('客户不存在');
      }

      const customer = customers[0];

      // 所有权访问控制：非超级管理员仅能访问自己创建的客户
      if (currentUser && currentUser.role !== 'super_admin') {
        if (customer.createdBy && customer.createdBy !== currentUser.userId) {
          this.logger.warn(`Customer not found with email: ${email}`);
          throw new NotFoundException('客户不存在');
        }
      }

      this.logger.log(`Customer found with email: ${email}`);
      return customer;
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      this.logger.error(
        `Failed to find customer by email: ${error.message}`,
        error.stack,
      );
      throw new BadRequestException('查询客户失败');
    }
  }

  /**
   * 根据手机号查找客户
   */
  async findByPhone(
    phone: string,
    currentUser?: { userId: string; role: string },
  ): Promise<Customer> {
    this.logger.log(`Finding customer with phone: ${phone}`);

    try {
      const customers = await this.dynamodbService.query(
        this.tableName,
        'phone = :phone',
        { ':phone': phone },
        'PhoneIndex',
      );

      if (customers.length === 0) {
        this.logger.warn(`Customer not found with phone: ${phone}`);
        throw new NotFoundException('客户不存在');
      }

      const customer = customers[0];

      // 所有权访问控制：非超级管理员仅能访问自己创建的客户
      if (currentUser && currentUser.role !== 'super_admin') {
        if (customer.createdBy && customer.createdBy !== currentUser.userId) {
          this.logger.warn(`Customer not found with phone: ${phone}`);
          throw new NotFoundException('客户不存在');
        }
      }

      this.logger.log(`Customer found with phone: ${phone}`);
      return customer;
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      this.logger.error(
        `Failed to find customer by phone: ${error.message}`,
        error.stack,
      );
      throw new BadRequestException('查询客户失败');
    }
  }

  /**
   * 更新客户信息
   */
  async update(
    customerId: string,
    updateCustomerDto: UpdateCustomerDto,
    currentUser: { userId: string; role: string },
  ): Promise<Customer> {
    this.logger.log(`Updating customer with ID: ${customerId}`);

    // 检查客户是否存在
    const existingCustomer = await this.findOne(customerId, currentUser);

    // 如果更新邮箱，检查新邮箱是否已被其他客户使用
    if (
      updateCustomerDto.email &&
      updateCustomerDto.email !== existingCustomer.email
    ) {
      await this.checkEmailExists(updateCustomerDto.email, customerId);
    }

    // 如果更新手机号，检查新手机号是否已被其他客户使用
    if (
      updateCustomerDto.phone &&
      updateCustomerDto.phone !== existingCustomer.phone
    ) {
      await this.checkPhoneExists(updateCustomerDto.phone, customerId);
    }

    try {
      // 构建更新表达式
      let updateExpression = 'SET #updatedAt = :updatedAt';
      const expressionAttributeNames = { '#updatedAt': 'updatedAt' };
      const expressionAttributeValues = {
        ':updatedAt': new Date().toISOString(),
      };

      // 动态构建更新字段
      Object.keys(updateCustomerDto).forEach((key, index) => {
        const attrName = `#attr${index}`;
        const attrValue = `:val${index}`;
        updateExpression += `, ${attrName} = ${attrValue}`;
        expressionAttributeNames[attrName] = key;
        expressionAttributeValues[attrValue] = updateCustomerDto[key];
      });

      const updatedCustomer = await this.dynamodbService.update(
        this.tableName,
        { customerId },
        updateExpression,
        expressionAttributeValues,
        expressionAttributeNames,
      );

      this.logger.log(`Customer updated successfully: ${customerId}`);
      return updatedCustomer;
    } catch (error) {
      this.logger.error(
        `Failed to update customer: ${error.message}`,
        error.stack,
      );
      throw new BadRequestException('更新客户失败');
    }
  }

  /**
   * 删除客户
   */
  async remove(
    customerId: string,
    currentUser: { userId: string; role: string },
  ): Promise<{ message: string }> {
    this.logger.log(`Deleting customer with ID: ${customerId}`);

    // 检查客户是否存在
    await this.findOne(customerId, currentUser);

    try {
      await this.dynamodbService.delete(this.tableName, { customerId });
      this.logger.log(`Customer deleted successfully: ${customerId}`);
      return { message: '客户删除成功' };
    } catch (error) {
      this.logger.error(
        `Failed to delete customer: ${error.message}`,
        error.stack,
      );
      throw new BadRequestException('删除客户失败');
    }
  }

  /**
   * 检查邮箱是否已存在
   * @param email 邮箱
   * @param excludeCustomerId 排除的客户ID（用于更新操作）
   */
  private async checkEmailExists(
    email: string,
    excludeCustomerId?: string,
  ): Promise<void> {
    try {
      const customers = await this.dynamodbService.query(
        this.tableName,
        'email = :email',
        { ':email': email },
        'EmailIndex',
      );

      if (
        customers.length > 0 &&
        customers[0].customerId !== excludeCustomerId
      ) {
        this.logger.warn(`Email already exists: ${email}`);
        throw new ConflictException('邮箱已被使用');
      }
    } catch (error) {
      if (error instanceof ConflictException) {
        throw error;
      }
      this.logger.error(
        `Error checking email existence: ${error.message}`,
        error.stack,
      );
      throw new BadRequestException('验证邮箱失败');
    }
  }

  /**
   * 检查手机号是否已存在
   * @param phone 手机号
   * @param excludeCustomerId 排除的客户ID（用于更新操作）
   */
  private async checkPhoneExists(
    phone: string,
    excludeCustomerId?: string,
  ): Promise<void> {
    try {
      const customers = await this.dynamodbService.query(
        this.tableName,
        'phone = :phone',
        { ':phone': phone },
        'PhoneIndex',
      );

      if (
        customers.length > 0 &&
        customers[0].customerId !== excludeCustomerId
      ) {
        this.logger.warn(`Phone already exists: ${phone}`);
        throw new ConflictException('手机号已被使用');
      }
    } catch (error) {
      if (error instanceof ConflictException) {
        throw error;
      }
      this.logger.error(
        `Error checking phone existence: ${error.message}`,
        error.stack,
      );
      throw new BadRequestException('验证手机号失败');
    }
  }

  /**
   * 获取所有客户数据用于导出
   */
  async getAllCustomersForExport(currentUser: {
    userId: string;
    role: string;
  }): Promise<Customer[]> {
    this.logger.log('Getting all customers for export');

    try {
      const allCustomers = await this.dynamodbService.scan(this.tableName);
      const filtered =
        currentUser.role === 'super_admin'
          ? allCustomers
          : allCustomers.filter((c) => c.createdBy === currentUser.userId);

      // 按创建时间排序
      filtered.sort(
        (a, b) =>
          new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime(),
      );

      this.logger.log(`Retrieved ${filtered.length} customers for export`);
      return filtered;
    } catch (error) {
      this.logger.error(
        `Failed to get customers for export: ${error.message}`,
        error.stack,
      );
      throw new BadRequestException('获取客户数据失败');
    }
  }

  /**
   * 生成Excel文件缓冲区
   */
  async generateExcelBuffer(customers: Customer[]): Promise<Buffer> {
    this.logger.log(`Generating Excel file for ${customers.length} customers`);

    try {
      const workbook = new Excel.Workbook();
      const worksheet = workbook.addWorksheet('客户数据');

      // 设置列标题
      const headers = [
        { header: '客户ID', key: 'customerId', width: 20 },
        { header: '邮箱', key: 'email', width: 25 },
        { header: '手机号', key: 'phone', width: 18 },
        { header: '姓', key: 'lastName', width: 10 },
        { header: '名', key: 'firstName', width: 10 },
        { header: '身份证件类型', key: 'idType', width: 15 },
        { header: '身份证件号码', key: 'idNumber', width: 20 },
        { header: '出生日期', key: 'dateOfBirth', width: 12 },
        { header: '联系地址', key: 'address', width: 30 },
        { header: '风险承受等级', key: 'riskLevel', width: 15 },
        { header: '客户状态', key: 'status', width: 12 },
        { header: '创建时间', key: 'createdAt', width: 20 },
        { header: '更新时间', key: 'updatedAt', width: 20 },
      ];

      worksheet.columns = headers;

      // 设置标题行样式
      const headerRow = worksheet.getRow(1);
      headerRow.font = { bold: true };
      headerRow.fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FFE0E0E0' },
      };

      // 添加数据行
      customers.forEach((customer) => {
        worksheet.addRow({
          customerId: customer.customerId,
          email: customer.email,
          phone: customer.phone,
          lastName: customer.lastName,
          firstName: customer.firstName,
          idType: customer.idType,
          idNumber: customer.idNumber,
          dateOfBirth: customer.dateOfBirth,
          address: customer.address,
          riskLevel: customer.riskLevel,
          status: customer.status,
          createdAt: new Date(customer.createdAt).toLocaleString('zh-CN'),
          updatedAt: new Date(customer.updatedAt).toLocaleString('zh-CN'),
        });
      });

      // 生成缓冲区
      const buffer = await workbook.xlsx.writeBuffer();
      this.logger.log('Excel file generated successfully');
      return Buffer.from(buffer);
    } catch (error) {
      this.logger.error(
        `Failed to generate Excel file: ${error.message}`,
        error.stack,
      );
      throw new BadRequestException('生成Excel文件失败');
    }
  }

  /**
   * 从Excel文件导入客户数据
   */
  async importCustomersFromExcel(
    file: Express.Multer.File,
    createdBy: string,
  ): Promise<ImportResultDto> {
    if (!file) {
      throw new BadRequestException('未提供文件');
    }

    this.logger.log(
      `Importing customers from Excel file: ${file.originalname}`,
    );

    // 检查文件类型
    const validMimeTypes = [
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', // .xlsx
      'application/vnd.ms-excel', // .xls
    ];

    if (!validMimeTypes.includes(file.mimetype)) {
      throw new UnsupportedMediaTypeException(
        '文件格式不支持，请上传Excel文件(.xlsx或.xls)',
      );
    }

    try {
      // 解析Excel文件
      const workbook = new Excel.Workbook();
      await workbook.xlsx.load(file.buffer as any);

      const worksheet = workbook.getWorksheet(1); // 获取第一个工作表
      if (!worksheet) {
        throw new BadRequestException('Excel文件中没有找到工作表');
      }

      // 验证Excel数据
      const { validData, errors } = await this.validateExcelData(worksheet);

      // 并发导入，有上限控制
      const concurrency = parseInt(process.env.IMPORT_CONCURRENCY || '4', 10);
      type ItemResult =
        | { kind: 'success' }
        | { kind: 'skipped'; detail: ImportErrorDetail }
        | { kind: 'failure'; detail: ImportErrorDetail };

      const taskMapper = async (data: any): Promise<ItemResult> => {
        try {
          // 检查邮箱和手机号是否已存在
          const [emailExists, phoneExists] = await Promise.all([
            this.isEmailExists(data.email),
            this.isPhoneExists(data.phone),
          ]);

          if (emailExists || phoneExists) {
            return {
              kind: 'skipped',
              detail: {
                row: data.rowNumber,
                error: emailExists ? '邮箱已存在' : '手机号已存在',
                data,
              },
            };
          }

          // 生成用户名与默认密码（用于创建登录账号）
          const username = this.buildUsernameFromPhone(data.phone);
          const password = this.getDefaultCustomerPassword();

          await this.create(
            {
              email: data.email,
              username,
              password,
              phone: data.phone,
              firstName: data.firstName,
              lastName: data.lastName,
              idType: data.idType as IdType,
              idNumber: data.idNumber,
              dateOfBirth: data.dateOfBirth,
              address: data.address,
              riskLevel: data.riskLevel as RiskLevel,
              status: data.status as CustomerStatus,
            },
            createdBy,
          );

          return { kind: 'success' };
        } catch (error) {
          return {
            kind: 'failure',
            detail: {
              row: data.rowNumber,
              error:
                (error && (error.message || error.toString())) || '导入失败',
              data,
            },
          };
        }
      };

      const results = await this.mapWithConcurrency(
        validData,
        Math.max(1, concurrency),
        taskMapper,
      );

      // 统计
      const successCount = results.filter((r) => r.kind === 'success').length;
      const skippedItems = results.filter(
        (r): r is Extract<ItemResult, { kind: 'skipped' }> =>
          r.kind === 'skipped',
      );
      const failureItems = results.filter(
        (r): r is Extract<ItemResult, { kind: 'failure' }> =>
          r.kind === 'failure',
      );
      const skippedCount = skippedItems.length;
      let failureCount = errors.length + failureItems.length;
      const importErrors: ImportErrorDetail[] = [
        ...skippedItems.map((i) => i.detail),
        ...failureItems.map((i) => i.detail),
      ];

      // 合并所有错误
      const allErrors = [...errors, ...importErrors];

      // 构建导入结果
      const totalCount = successCount + failureCount + skippedCount;
      const result: ImportResultDto = {
        successCount,
        failureCount,
        skippedCount,
        totalCount,
        errors: allErrors,
        message: `导入完成：成功 ${successCount} 条，失败 ${failureCount} 条，跳过 ${skippedCount} 条`,
      };

      this.logger.log(`Import completed: ${result.message}`);
      return result;
    } catch (error) {
      this.logger.error(
        `Failed to import customers: ${error.message}`,
        error.stack,
      );
      throw new BadRequestException(`导入客户数据失败: ${error.message}`);
    }
  }

  /**
   * 获取默认客户密码（优先环境变量，不符合策略则回退安全默认值）
   */
  private getDefaultCustomerPassword(): string {
    const envPassword =
      this.configService.get<string>('DEFAULT_CUSTOMER_PASSWORD') ||
      process.env.DEFAULT_CUSTOMER_PASSWORD ||
      this.configService.get<string>('AUTH_DEFAULT_CUSTOMER_PASSWORD') ||
      process.env.AUTH_DEFAULT_CUSTOMER_PASSWORD;

    // Cognito 常见密码策略：>=8，含大写/小写/数字/特殊字符
    const meetsPolicy = (pwd: string) =>
      typeof pwd === 'string' &&
      pwd.length >= 8 &&
      /[A-Z]/.test(pwd) &&
      /[a-z]/.test(pwd) &&
      /\d/.test(pwd) &&
      /[@$!%*?&.#_\-]/.test(pwd);

    if (envPassword && meetsPolicy(envPassword)) {
      return envPassword;
    }

    // 安全默认值（符合 Cognito 复杂度要求）
    const fallback = 'Tmp#Customer123';
    if (!meetsPolicy(envPassword || '')) {
      this.logger.warn(
        'Environment default password is missing or too weak, using fallback default password',
      );
    }
    return fallback;
  }

  /**
   * 基于邮箱生成合法、非邮箱格式的用户名，尽量保证唯一
   */
  private async generateCustomerUsername(email: string): Promise<string> {
    const prefix = (email || '').split('@')[0] || 'user';
    const safe = prefix.replace(/[^a-zA-Z0-9_\-]/g, '_').slice(0, 16);

    // 生成带随机后缀的用户名，避免与已有用户冲突，长度控制 <= 30
    const base = `cust_${safe}`; // 最长 5 + 1 + 16 = 22

    for (let i = 0; i < 5; i++) {
      const suffix = Math.random().toString(36).slice(2, 8); // 6位
      const candidate = `${base}_${suffix}`; // 最长 22 + 1 + 6 = 29

      // 检查是否已存在
      try {
        const existing = await this.dynamodbService.get('users', {
          userId: candidate,
        });
        if (!existing) return candidate;
      } catch (_) {
        // 如检查失败，直接返回候选，交由下游冲突处理
        return candidate;
      }
    }

    // 退化处理：仍返回一个候选（极低概率冲突，由下游处理）
    return `${base}_${Date.now().toString().slice(-6)}`;
  }

  /**
   * 使用电话号码构建用户名：去除非数字字符，保证非空
   */
  private buildUsernameFromPhone(phone: string): string {
    const digits = (phone || '').replace(/\D/g, '');
    if (digits.length > 0) return digits;
    // 极端情况下仍为空，退化到时间戳用户名
    return `cust_${Date.now().toString().slice(-10)}`;
  }

  /**
   * 简单的并发控制映射器
   */
  private async mapWithConcurrency<T, R>(
    items: T[],
    limit: number,
    mapper: (item: T) => Promise<R>,
  ): Promise<R[]> {
    const results: R[] = new Array(items.length);
    let index = 0;
    const workers = Array.from({ length: Math.min(limit, items.length) }).map(
      async () => {
        while (true) {
          const current = index++;
          if (current >= items.length) break;
          try {
            results[current] = await mapper(items[current]);
          } catch (e) {
            // 将异常包裹为 mapper 内部应返回的形式交由上层统计
            results[current] = e as any as R;
          }
        }
      },
    );
    await Promise.all(workers);
    return results;
  }

  /**
   * 验证Excel数据
   */
  private async validateExcelData(
    worksheet: Excel.Worksheet,
  ): Promise<{ validData: any[]; errors: ImportErrorDetail[] }> {
    const validData: any[] = [];
    const errors: ImportErrorDetail[] = [];

    // 获取标题行
    const headerRow = worksheet.getRow(1);
    const headers: string[] = [];

    headerRow.eachCell((cell, colNumber) => {
      headers[colNumber - 1] = cell.value?.toString().trim() || '';
    });

    // 验证必要的列是否存在
    const requiredColumns = [
      '邮箱',
      '手机号',
      '姓',
      '名',
      '身份证件类型',
      '身份证件号码',
      '出生日期',
      '联系地址',
      '风险承受等级',
    ];
    const missingColumns = requiredColumns.filter(
      (col) => !headers.includes(col),
    );

    if (missingColumns.length > 0) {
      throw new BadRequestException(
        `Excel文件缺少必要的列: ${missingColumns.join(', ')}`,
      );
    }

    // 处理每一行数据
    worksheet.eachRow((row, rowNumber) => {
      // 跳过标题行
      if (rowNumber === 1) return;

      const rowData: any = { rowNumber };
      let hasError = false;

      // 映射列名到字段名
      const columnMapping: { [key: string]: string } = {
        邮箱: 'email',
        手机号: 'phone',
        姓: 'lastName',
        名: 'firstName',
        身份证件类型: 'idType',
        身份证件号码: 'idNumber',
        出生日期: 'dateOfBirth',
        联系地址: 'address',
        风险承受等级: 'riskLevel',
        客户状态: 'status',
      };

      // 获取每个单元格的值（兼容超链接/富文本/公式等）
      headers.forEach((header, colIndex) => {
        const fieldName = columnMapping[header];
        if (!fieldName) return;

        const cell = row.getCell(colIndex + 1);
        let value: any = cell?.value as any;

        // 统一提取为字符串
        if (value instanceof Date) {
          // 日期单元格
          value = value.toISOString();
        } else if (value && typeof value === 'object') {
          // exceljs 超链接: { text: string, hyperlink: string }
          if (typeof (value as any).text === 'string') {
            value = (value as any).text;
          }
          // exceljs 富文本: { richText: [{ text: string, ...}, ...] }
          else if (Array.isArray((value as any).richText)) {
            value = (value as any).richText
              .map((t: any) => t.text || '')
              .join('');
          }
          // 公式: { formula: string, result?: any }
          else if ('result' in (value as any)) {
            value = (value as any).result;
          }
          // 其他对象，尽量取字符串化的安全路径（避免 [object Object]）
          else {
            value = '';
          }
        }

        if (value !== null && value !== undefined) {
          // 出生日期规范化为 YYYY-MM-DD
          if (fieldName === 'dateOfBirth') {
            // 如果是 ISO 或日期字符串，尽量裁剪成 YYYY-MM-DD
            const iso = value.toString();
            const m = iso.match(/^(\d{4})-(\d{2})-(\d{2})/);
            value = m ? `${m[1]}-${m[2]}-${m[3]}` : iso.trim();
          } else {
            value = value.toString().trim();
          }
        }

        rowData[fieldName] = value;
      });

      // 验证必填字段
      const rowErrors: string[] = [];

      // 验证邮箱
      if (!rowData.email) {
        rowErrors.push('邮箱不能为空');
      } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(rowData.email)) {
        rowErrors.push('邮箱格式不正确');
      }

      // 验证手机号
      if (!rowData.phone) {
        rowErrors.push('手机号不能为空');
      } else if (!/^(\+86\s?)?1[3-9]\d{9}$/.test(rowData.phone)) {
        rowErrors.push('手机号格式不正确');
      }

      // 验证姓名
      if (!rowData.firstName) rowErrors.push('名不能为空');
      if (!rowData.lastName) rowErrors.push('姓不能为空');

      // 验证身份证件类型
      if (!rowData.idType) {
        rowErrors.push('身份证件类型不能为空');
      } else if (!Object.values(IdType).includes(rowData.idType)) {
        rowErrors.push(
          `身份证件类型必须是以下之一: ${Object.values(IdType).join(', ')}`,
        );
      }

      // 验证身份证件号码
      if (!rowData.idNumber) rowErrors.push('身份证件号码不能为空');

      // 验证出生日期
      if (!rowData.dateOfBirth) {
        rowErrors.push('出生日期不能为空');
      } else if (!/^\d{4}-\d{2}-\d{2}$/.test(rowData.dateOfBirth)) {
        rowErrors.push('出生日期格式不正确，应为YYYY-MM-DD');
      }

      // 验证地址
      if (!rowData.address) rowErrors.push('联系地址不能为空');

      // 验证风险等级
      if (!rowData.riskLevel) {
        rowErrors.push('风险承受等级不能为空');
      } else if (!Object.values(RiskLevel).includes(rowData.riskLevel)) {
        rowErrors.push(
          `风险承受等级必须是以下之一: ${Object.values(RiskLevel).join(', ')}`,
        );
      }

      // 验证客户状态（可选）
      if (
        rowData.status &&
        !Object.values(CustomerStatus).includes(rowData.status)
      ) {
        rowErrors.push(
          `客户状态必须是以下之一: ${Object.values(CustomerStatus).join(', ')}`,
        );
      } else if (!rowData.status) {
        // 设置默认状态
        rowData.status = CustomerStatus.ACTIVE;
      }

      // 处理验证结果
      if (rowErrors.length > 0) {
        errors.push({
          row: rowNumber,
          error: rowErrors.join('; '),
          data: rowData,
        });
      } else {
        validData.push(rowData);
      }
    });

    return { validData, errors };
  }

  /**
   * 检查邮箱是否存在（不抛出异常）
   */
  private async isEmailExists(email: string): Promise<boolean> {
    try {
      const customers = await this.dynamodbService.query(
        this.tableName,
        'email = :email',
        { ':email': email },
        'EmailIndex',
      );
      return customers.length > 0;
    } catch (error) {
      return false;
    }
  }

  /**
   * 检查手机号是否存在（不抛出异常）
   */
  private async isPhoneExists(phone: string): Promise<boolean> {
    try {
      const customers = await this.dynamodbService.query(
        this.tableName,
        'phone = :phone',
        { ':phone': phone },
        'PhoneIndex',
      );
      return customers.length > 0;
    } catch (error) {
      return false;
    }
  }
}
