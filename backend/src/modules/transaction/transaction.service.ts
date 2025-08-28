import {
  Injectable,
  NotFoundException,
  BadRequestException,
  Logger,
  UnsupportedMediaTypeException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { v4 as uuidv4 } from 'uuid';
import * as Excel from 'exceljs';

import { DynamodbService } from '../../database/dynamodb.service';
import { CreateTransactionDto } from './dto/create-transaction.dto';
import { UpdateTransactionDto } from './dto/update-transaction.dto';
import {
  QueryTransactionDto,
  TransactionListResponse,
} from './dto/query-transaction.dto';
import {
  Transaction,
  TransactionStatus,
  TransactionType,
  PaymentMethod,
} from './entities/transaction.entity';
import { ImportResultDto, ImportErrorDetail } from './dto/import-result.dto';

@Injectable()
export class TransactionService {
  private readonly logger = new Logger(TransactionService.name);
  private readonly tableName: string;
  private readonly customerTableName: string;
  private readonly productTableName: string;

  constructor(
    private readonly dynamodbService: DynamodbService,
    private readonly configService: ConfigService,
  ) {
    this.tableName = this.configService.get<string>(
      'database.tables.customerProductTransactions',
    );
    this.customerTableName = this.configService.get<string>(
      'database.tables.customers',
    );
    this.productTableName = this.configService.get<string>(
      'database.tables.products',
    );
  }

  async create(dto: CreateTransactionDto): Promise<Transaction> {
    // 强校验：客户与产品必须存在
    const [customer, product] = await Promise.all([
      this.dynamodbService.get(this.customerTableName, {
        customerId: dto.customerId,
      }),
      this.dynamodbService.get(this.productTableName, {
        productId: dto.productId,
      }),
    ]);

    if (!customer) {
      throw new NotFoundException('客户不存在');
    }
    if (!product) {
      throw new NotFoundException('产品不存在');
    }

    const now = new Date().toISOString();
    const transactionId = `txn_${uuidv4()}`;

    const item: Transaction = {
      transactionId,
      ...dto,
      totalAmount: dto.totalAmount ?? dto.unitPrice * dto.quantity,
      transactionStatus: dto.transactionStatus || TransactionStatus.PENDING,
      createdAt: now,
      updatedAt: now,
    };

    await this.dynamodbService.put(this.tableName, item);
    return item;
  }

  async findAll(query: QueryTransactionDto): Promise<TransactionListResponse> {
    const items = await this.dynamodbService.scan(this.tableName);

    let filtered = items;
    if (query.customerId) {
      filtered = filtered.filter((i) => i.customerId === query.customerId);
    }
    if (query.productId) {
      filtered = filtered.filter((i) => i.productId === query.productId);
    }
    if (query.transactionStatus) {
      filtered = filtered.filter(
        (i) => i.transactionStatus === query.transactionStatus,
      );
    }

    filtered.sort((a, b) => {
      const aVal = a[query.sortBy] || '';
      const bVal = b[query.sortBy] || '';
      if (query.sortOrder === 'asc')
        return String(aVal).localeCompare(String(bVal));
      return String(bVal).localeCompare(String(aVal));
    });

    const total = filtered.length;
    const totalPages = Math.ceil(total / query.limit);
    const start = (query.page - 1) * query.limit;
    const end = start + query.limit;
    const pageItems = filtered.slice(start, end);

    // 补充中文可读名称：客户姓名、产品名称
    // 为避免逐条查询，这里一次性扫描客户与产品表并构建映射
    const [allCustomers, allProducts] = await Promise.all([
      this.dynamodbService.scan(this.customerTableName),
      this.dynamodbService.scan(this.productTableName),
    ]);

    const customerMap = new Map<string, any>();
    for (const c of allCustomers) customerMap.set(c.customerId, c);
    const productMap = new Map<string, any>();
    for (const p of allProducts) productMap.set(p.productId, p);

    const data = pageItems.map((t: any) => {
      const customer = customerMap.get(t.customerId);
      const product = productMap.get(t.productId);
      const customerName = customer
        ? `${customer.lastName || ''}${customer.firstName || ''}`
        : undefined;
      const productName = product ? product.productName : undefined;
      return {
        ...t,
        customerName,
        productName,
      };
    });

    return { data, total, page: query.page, limit: query.limit, totalPages };
  }

  async findOne(transactionId: string): Promise<Transaction> {
    // 为兼容不同表键模式，使用扫描+过滤按 transactionId 精确匹配
    const items = await this.dynamodbService.scan(
      this.tableName,
      '#tid = :tid',
      { ':tid': transactionId },
      { '#tid': 'transactionId' },
    );

    const item = items?.[0];
    if (!item) throw new NotFoundException('记录不存在');

    // 详情补充：客户姓名与产品名称
    const [customer, product] = await Promise.all([
      item.customerId
        ? this.dynamodbService.get(this.customerTableName, {
            customerId: item.customerId,
          })
        : Promise.resolve(undefined),
      item.productId
        ? this.dynamodbService.get(this.productTableName, {
            productId: item.productId,
          })
        : Promise.resolve(undefined),
    ]);

    const customerName = customer
      ? `${customer.lastName || ''}${customer.firstName || ''}`
      : undefined;
    const productName = product ? product.productName : undefined;

    return { ...(item as any), customerName, productName } as Transaction;
  }

  async update(
    transactionId: string,
    dto: UpdateTransactionDto,
  ): Promise<Transaction> {
    // 先获取现有记录以拿到 sort key（createdAt）
    const existing = await this.findOne(transactionId);

    if (dto.transactionId && dto.transactionId !== transactionId) {
      throw new BadRequestException('交易ID与参数不一致');
    }

    // 若提供了 customerId 或 productId，则进行存在性校验
    const checks: Promise<any>[] = [];
    if (dto.customerId) {
      checks.push(
        this.dynamodbService.get(this.customerTableName, {
          customerId: dto.customerId,
        }),
      );
    } else {
      checks.push(Promise.resolve(undefined));
    }

    if (dto.productId) {
      checks.push(
        this.dynamodbService.get(this.productTableName, {
          productId: dto.productId,
        }),
      );
    } else {
      checks.push(Promise.resolve(undefined));
    }

    const [customerMaybe, productMaybe] = await Promise.all(checks);
    if (dto.customerId && !customerMaybe) {
      throw new NotFoundException('客户不存在');
    }
    if (dto.productId && !productMaybe) {
      throw new NotFoundException('产品不存在');
    }

    let updateExpression = 'SET #updatedAt = :updatedAt';
    const names: Record<string, string> = { '#updatedAt': 'updatedAt' };
    const values: Record<string, any> = {
      ':updatedAt': new Date().toISOString(),
    };

    Object.keys(dto).forEach((key, i) => {
      // 不允许更新主键字段
      if (key === 'transactionId' || key === 'createdAt') return;
      const attr = `#attr${i}`;
      const val = `:val${i}`;
      updateExpression += `, ${attr} = ${val}`;
      names[attr] = key;
      values[val] = (dto as any)[key];
    });

    const updated = await this.dynamodbService.update(
      this.tableName,
      { transactionId, createdAt: existing.createdAt },
      updateExpression,
      values,
      names,
    );

    // 返回详情时补充客户/产品名称，复用 findOne 保持一致
    return this.findOne(transactionId);
  }

  async remove(transactionId: string): Promise<{ message: string }> {
    const existing = await this.findOne(transactionId);
    await this.dynamodbService.delete(this.tableName, {
      transactionId,
      createdAt: existing.createdAt,
    });
    return { message: '删除成功' };
  }

  async getAllForExport(): Promise<Transaction[]> {
    const items = await this.dynamodbService.scan(this.tableName);

    // 为导出补充中文名称，避免 Excel 中只有 ID
    const [allCustomers, allProducts] = await Promise.all([
      this.dynamodbService.scan(this.customerTableName),
      this.dynamodbService.scan(this.productTableName),
    ]);

    const customerMap = new Map<string, any>();
    for (const c of allCustomers) customerMap.set(c.customerId, c);
    const productMap = new Map<string, any>();
    for (const p of allProducts) productMap.set(p.productId, p);

    const enriched = items.map((t: any) => {
      const customer = customerMap.get(t.customerId);
      const product = productMap.get(t.productId);
      const customerName = customer
        ? `${customer.lastName || ''}${customer.firstName || ''}`
        : undefined;
      const productName = product ? product.productName : undefined;
      return { ...t, customerName, productName } as Transaction;
    });

    enriched.sort(
      (a, b) =>
        new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime(),
    );
    return enriched;
  }

  async generateExcelBuffer(transactions: Transaction[]): Promise<Buffer> {
    const workbook = new Excel.Workbook();
    const sheet = workbook.addWorksheet('交易记录');

    sheet.columns = [
      { header: '交易ID', key: 'transactionId', width: 20 },
      { header: '客户ID', key: 'customerId', width: 20 },
      { header: '客户姓名', key: 'customerName', width: 20 },
      { header: '产品ID', key: 'productId', width: 20 },
      { header: '产品名称', key: 'productName', width: 20 },
      { header: '交易类型', key: 'transactionType', width: 12 },
      { header: '数量', key: 'quantity', width: 10 },
      { header: '单价', key: 'unitPrice', width: 10 },
      { header: '总金额', key: 'totalAmount', width: 15 },
      { header: '支付方式', key: 'paymentMethod', width: 15 },
      { header: '交易状态', key: 'transactionStatus', width: 15 },
      { header: '预期到期日期', key: 'expectedMaturityDate', width: 15 },
      { header: '实际收益率', key: 'actualReturnRate', width: 12 },
      { header: '备注', key: 'notes', width: 20 },
      { header: '创建时间', key: 'createdAt', width: 20 },
      { header: '更新时间', key: 'updatedAt', width: 20 },
      { header: '完成时间', key: 'completedAt', width: 20 },
    ];

    transactions.forEach((t) => sheet.addRow(t));

    const buffer = await workbook.xlsx.writeBuffer();
    return Buffer.from(buffer);
  }

  async importFromExcel(file: Express.Multer.File): Promise<ImportResultDto> {
    if (!file.originalname.toLowerCase().endsWith('.xlsx')) {
      throw new UnsupportedMediaTypeException('仅支持xlsx格式');
    }

    const workbook = new Excel.Workbook();
    await workbook.xlsx.load(file.buffer as any);
    const worksheet = workbook.worksheets[0];

    // 动态按表头映射，防止列位移：导出顺序包含 transactionId 等
    const headerRow = worksheet.getRow(1);
    const headerMap = new Map<string, number>();
    headerRow.eachCell((cell, colNumber) => {
      const title = String(cell.value || '').trim();
      if (title) headerMap.set(title, colNumber);
    });
    const getText = (title: string, row: Excel.Row) => {
      const col = headerMap.get(title);
      if (!col) return '';
      return row.getCell(col).text?.trim?.() || '';
    };
    const getNumber = (title: string, row: Excel.Row) => {
      const col = headerMap.get(title);
      if (!col) return undefined as any;
      const val = row.getCell(col).value as any;
      if (val === null || val === undefined || val === '')
        return undefined as any;
      const n = Number(val);
      return Number.isFinite(n) ? n : NaN;
    };

    const rows: any[] = [];
    worksheet.eachRow((row, rowNumber) => {
      if (rowNumber === 1) return;
      const rawVals: any = (row as any).values;
      const arrVals: any[] = Array.isArray(rawVals) ? rawVals : [];
      const isEmpty = arrVals
        .slice(1)
        .every(
          (v: any) => v === null || v === undefined || String(v).trim() === '',
        );
      if (isEmpty) return;

      const data = {
        customerId: getText('客户ID', row),
        productId: getText('产品ID', row),
        transactionType: getText('交易类型', row) as TransactionType,
        quantity: getNumber('数量', row),
        unitPrice: getNumber('单价', row),
        totalAmount: getNumber('总金额', row),
        paymentMethod: getText('支付方式', row) as PaymentMethod,
        transactionStatus:
          (getText('交易状态', row) as TransactionStatus) ||
          TransactionStatus.PENDING,
        expectedMaturityDate: getText('预期到期日期', row),
        actualReturnRate:
          getNumber('实际收益率', row) !== undefined
            ? getNumber('实际收益率', row)
            : undefined,
        notes: getText('备注', row),
      } as any;
      rows.push({ data, rowNumber });
    });

    let successCount = 0;
    const errors: ImportErrorDetail[] = [];

    for (const item of rows) {
      const d = item.data as any;
      const rowErrors: string[] = [];

      if (!d.customerId) rowErrors.push('客户ID不能为空');
      if (!d.productId) rowErrors.push('产品ID不能为空');

      const numericFields: Array<[string, string]> = [
        ['quantity', '数量'],
        ['unitPrice', '单价'],
        ['totalAmount', '总金额'],
      ];
      for (const [k, label] of numericFields) {
        const v = d[k];
        if (v === undefined || v === null || v === '') {
          rowErrors.push(`${label}不能为空`);
        } else if (Number.isNaN(v)) {
          rowErrors.push(`${label}必须是数字`);
        }
      }

      if (rowErrors.length > 0) {
        errors.push({
          row: item.rowNumber,
          error: rowErrors.join('; '),
          data: d,
        });
        continue;
      }

      try {
        await this.create(d);
        successCount++;
      } catch (e: any) {
        errors.push({
          row: item.rowNumber,
          error: e?.message || '导入失败',
          data: d,
        });
      }
    }

    return {
      successCount,
      failureCount: errors.length,
      skippedCount: 0,
      totalCount: rows.length,
      errors,
      message: `导入完成：成功 ${successCount} 条，失败 ${errors.length} 条`,
    };
  }
}
