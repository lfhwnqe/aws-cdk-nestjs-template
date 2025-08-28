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
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import { QueryProductDto, ProductListResponse } from './dto/query-product.dto';
import { Product, ProductStatus, ProductType } from './entities/product.entity';
import { ImportResultDto, ImportErrorDetail } from './dto/import-result.dto';

@Injectable()
export class ProductService {
  private readonly logger = new Logger(ProductService.name);
  private readonly tableName: string;

  constructor(
    private readonly dynamodbService: DynamodbService,
    private readonly configService: ConfigService,
  ) {
    this.tableName = this.configService.get<string>('database.tables.products');
  }

  async create(
    createDto: CreateProductDto,
    createdBy: string,
  ): Promise<Product> {
    const now = new Date().toISOString();
    const productId = `prod_${uuidv4()}`;

    const product: Product = {
      productId,
      ...createDto,
      status: createDto.status || ProductStatus.ACTIVE,
      createdAt: now,
      updatedAt: now,
      createdBy,
    };

    await this.dynamodbService.put(this.tableName, product);
    return product;
  }

  async findAll(
    query: QueryProductDto,
    currentUser: { userId: string; role: string },
  ): Promise<ProductListResponse> {
    const all = await this.dynamodbService.scan(this.tableName);

    let items = all;
    // 非超级管理员仅能查看自己创建的资源
    if ((currentUser?.role || 'user') !== 'super_admin') {
      items = items.filter((p) => p.createdBy === currentUser?.userId);
    }
    if (query.search) {
      const term = query.search.toLowerCase();
      items = items.filter((p) => p.productName.toLowerCase().includes(term));
    }
    if (query.productType) {
      items = items.filter((p) => p.productType === query.productType);
    }
    if (query.status) {
      items = items.filter((p) => p.status === query.status);
    }

    items.sort((a, b) => {
      const aVal = a[query.sortBy] || '';
      const bVal = b[query.sortBy] || '';
      if (query.sortOrder === 'asc')
        return String(aVal).localeCompare(String(bVal));
      return String(bVal).localeCompare(String(aVal));
    });

    const total = items.length;
    const totalPages = Math.ceil(total / query.limit);
    const start = (query.page - 1) * query.limit;
    const end = start + query.limit;
    const data = items.slice(start, end);

    return { data, total, page: query.page, limit: query.limit, totalPages };
  }

  async findOne(
    productId: string,
    currentUser?: { userId: string; role: string },
  ): Promise<Product> {
    const product = await this.dynamodbService.get(this.tableName, {
      productId,
    });
    if (!product) throw new NotFoundException('产品不存在');
    // 详情访问控制：非超级管理员仅能访问自己资源
    if (currentUser && currentUser.role !== 'super_admin') {
      if (product.createdBy && product.createdBy !== currentUser.userId) {
        throw new NotFoundException('产品不存在');
      }
    }
    return product;
  }

  async update(
    productId: string,
    updateDto: UpdateProductDto,
    currentUser: { userId: string; role: string },
  ): Promise<Product> {
    const existing = await this.findOne(productId);
    if (
      currentUser.role !== 'super_admin' &&
      existing.createdBy !== currentUser.userId
    ) {
      throw new NotFoundException('产品不存在');
    }

    let updateExpression = 'SET #updatedAt = :updatedAt';
    const names: Record<string, string> = { '#updatedAt': 'updatedAt' };
    const values: Record<string, any> = {
      ':updatedAt': new Date().toISOString(),
    };

    // 过滤不允许更新的字段（如主键/只读字段）
    const disallowed = new Set(['productId', 'createdAt', 'createdBy']);
    const allowedKeys = Object.keys(updateDto).filter(
      (k) => !disallowed.has(k),
    );

    if (allowedKeys.length === 0) {
      // 仅更新时间也可视为成功，但便于前端提示，这里抛出参数无更新内容
      throw new BadRequestException('无可更新的字段');
    }

    allowedKeys.forEach((key, i) => {
      const attr = `#attr${i}`;
      const val = `:val${i}`;
      updateExpression += `, ${attr} = ${val}`;
      names[attr] = key;
      values[val] = (updateDto as any)[key];
    });

    const updated = await this.dynamodbService.update(
      this.tableName,
      { productId },
      updateExpression,
      values,
      names,
    );

    return updated;
  }

  async remove(
    productId: string,
    currentUser: { userId: string; role: string },
  ): Promise<{ message: string }> {
    const existing = await this.findOne(productId);
    if (
      currentUser.role !== 'super_admin' &&
      existing.createdBy !== currentUser.userId
    ) {
      throw new NotFoundException('产品不存在');
    }
    await this.dynamodbService.delete(this.tableName, { productId });
    return { message: '产品删除成功' };
  }

  async getAllForExport(currentUser: {
    userId: string;
    role: string;
  }): Promise<Product[]> {
    const items = await this.dynamodbService.scan(this.tableName);
    const filtered =
      currentUser.role === 'super_admin'
        ? items
        : items.filter((p) => p.createdBy === currentUser.userId);
    filtered.sort(
      (a, b) =>
        new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime(),
    );
    return filtered;
  }

  async generateExcelBuffer(products: Product[]): Promise<Buffer> {
    const workbook = new Excel.Workbook();
    const sheet = workbook.addWorksheet('产品数据');

    sheet.columns = [
      { header: '产品ID', key: 'productId', width: 20 },
      { header: '产品名称', key: 'productName', width: 20 },
      { header: '产品类型', key: 'productType', width: 15 },
      { header: '风险等级', key: 'riskLevel', width: 10 },
      { header: '最低投资金额', key: 'minInvestment', width: 15 },
      { header: '最高投资金额', key: 'maxInvestment', width: 15 },
      { header: '预期收益率', key: 'expectedReturn', width: 15 },
      { header: '结息日期', key: 'interestPaymentDate', width: 15 },
      { header: '产品期限', key: 'maturityPeriod', width: 12 },
      { header: '产品状态', key: 'status', width: 12 },
      { header: '销售开始日期', key: 'salesStartDate', width: 15 },
      { header: '销售结束日期', key: 'salesEndDate', width: 15 },
      { header: '创建时间', key: 'createdAt', width: 20 },
    ];

    products.forEach((p) => sheet.addRow(p));

    const buffer = await workbook.xlsx.writeBuffer();
    return Buffer.from(buffer);
  }

  async importFromExcel(
    file: Express.Multer.File,
    createdBy: string,
  ): Promise<ImportResultDto> {
    if (!file.originalname.toLowerCase().endsWith('.xlsx')) {
      throw new UnsupportedMediaTypeException('仅支持xlsx格式');
    }

    const workbook = new Excel.Workbook();
    await workbook.xlsx.load(file.buffer as any);
    const worksheet = workbook.worksheets[0];

    // 动态读取表头，按标题映射，避免列位移
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

    const rows: { data: Partial<CreateProductDto>; rowNumber: number }[] = [];
    worksheet.eachRow((row, rowNumber) => {
      if (rowNumber === 1) return; // 跳过表头

      // 跳过全空行
      const rawVals: any = (row as any).values;
      const arrVals: any[] = Array.isArray(rawVals) ? rawVals : [];
      const isEmpty = arrVals
        .slice(1)
        .every(
          (v: any) => v === null || v === undefined || String(v).trim() === '',
        );
      if (isEmpty) return;

      // 依据导出标题
      const data: any = {
        productName: getText('产品名称', row),
        productType: getText('产品类型', row) as ProductType,
        riskLevel: getText('风险等级', row) as any,
        minInvestment: getNumber('最低投资金额', row),
        maxInvestment: getNumber('最高投资金额', row),
        expectedReturn: getNumber('预期收益率', row),
        interestPaymentDate: getText('结息日期', row),
        maturityPeriod: getNumber('产品期限', row),
        status:
          (getText('产品状态', row) as ProductStatus) || ProductStatus.ACTIVE,
        salesStartDate: getText('销售开始日期', row),
        salesEndDate: getText('销售结束日期', row),
      };

      // 兼容可能额外的“产品描述”列（若导出没带此列则忽略）
      const desc = getText('产品描述', row);
      if (desc) data.description = desc;

      rows.push({ data, rowNumber });
    });

    let successCount = 0;
    const errors: ImportErrorDetail[] = [];

    for (const item of rows) {
      const rowErrors: string[] = [];
      const d = item.data as any;

      // 基础必填校验
      if (!d.productName) rowErrors.push('产品名称不能为空');
      if (
        !d.productType ||
        !Object.values(ProductType).includes(d.productType)
      ) {
        rowErrors.push(
          `产品类型无效，应为: ${Object.values(ProductType).join(', ')}`,
        );
      }
      if (!d.riskLevel) {
        rowErrors.push('风险等级不能为空');
      }
      // 数值校验：禁止 NaN
      const numericFields: Array<[keyof CreateProductDto, string]> = [
        ['minInvestment', '最低投资金额'],
        ['maxInvestment', '最高投资金额'],
        ['expectedReturn', '预期收益率'],
        ['maturityPeriod', '产品期限'],
      ];
      for (const [key, label] of numericFields) {
        const v = d[key as any];
        if (v === undefined || v === null || v === '') {
          rowErrors.push(`${label}不能为空`);
        } else if (Number.isNaN(v)) {
          rowErrors.push(`${label}必须是数字`);
        } else if (typeof v !== 'number') {
          rowErrors.push(`${label}类型错误`);
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
        await this.create(d as CreateProductDto, createdBy);
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
