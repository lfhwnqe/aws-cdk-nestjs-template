import {
  Injectable,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { DynamodbService } from '@/database/dynamodb.service';
import { CustomerService } from './customer.service';
import {
  QueryCustomerPurchasesDto,
  CustomerPurchaseListResponse,
} from './dto/query-customer-purchases.dto';

@Injectable()
export class CustomerPurchasesService {
  private readonly txnTable: string;
  private readonly productTable: string;
  private readonly customerTable: string;

  constructor(
    private readonly dynamodb: DynamodbService,
    private readonly config: ConfigService,
    private readonly customerService: CustomerService,
  ) {
    this.txnTable = this.config.get<string>(
      'database.tables.customerProductTransactions',
    );
    this.productTable = this.config.get<string>('database.tables.products');
    this.customerTable = this.config.get<string>('database.tables.customers');
  }

  private async getAllowedCustomerIds(currentUser: {
    userId: string;
    role: string;
  }): Promise<Set<string> | undefined> {
    // super admin: no restriction
    if (currentUser?.role === 'super_admin') return undefined;

    // customer: only own customerId (from users table)
    if (currentUser?.role === 'customer') {
      const userRecord = await this.dynamodb.get('users', {
        userId: currentUser.userId,
      });
      const cid = userRecord?.customerId;
      if (!cid) throw new BadRequestException('当前客户账号未绑定客户ID');
      return new Set([cid]);
    }

    // admin/user: customers created by this user
    const customers = await this.dynamodb.scan(
      this.customerTable,
      '#createdBy = :uid',
      { ':uid': currentUser.userId },
      { '#createdBy': 'createdBy' },
    );
    return new Set(customers.map((c: any) => c.customerId));
  }

  async listPurchases(
    query: QueryCustomerPurchasesDto,
    currentUser: { userId: string; role: string },
  ): Promise<CustomerPurchaseListResponse> {
    const allowed = await this.getAllowedCustomerIds(currentUser);

    // 获取交易记录
    let items = (await this.dynamodb.scan(this.txnTable)) as any[];
    if (allowed) {
      items = items.filter((i) => allowed.has(i.customerId));
    }
    if (query.productId)
      items = items.filter((i) => i.productId === query.productId);

    // 排序：按创建时间倒序
    items.sort(
      (a, b) =>
        new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
    );

    // 分页
    const total = items.length;
    const totalPages = Math.ceil(total / query.limit);
    const start = (query.page - 1) * query.limit;
    const end = start + query.limit;
    const pageItems = items.slice(start, end);

    // 补充客户/产品名称，便于前端阅读
    const [allProducts, allCustomers] = await Promise.all([
      this.dynamodb.scan(this.productTable),
      this.dynamodb.scan(this.customerTable),
    ]);

    const productMap = new Map<string, any>();
    for (const p of allProducts) productMap.set(p.productId, p);

    const customerMap = new Map<string, any>();
    for (const c of allCustomers) customerMap.set(c.customerId, c);

    const data = pageItems.map((t) => {
      const productName = productMap.get(t.productId)?.productName;
      const c = customerMap.get(t.customerId);
      const customerName = c
        ? `${c.lastName || ''}${c.firstName || ''}`
        : undefined;
      return { ...t, productName, customerName };
    });

    return { data, total, page: query.page, limit: query.limit, totalPages };
  }

  async getProductDetail(
    productId: string,
    currentUser: { userId: string; role: string },
  ) {
    const allowed = await this.getAllowedCustomerIds(currentUser);

    if (allowed) {
      // 非超级管理员需验证至少有一条允许范围内的购买记录
      const txns = (await this.dynamodb.scan(this.txnTable)) as any[];
      const match = txns.find(
        (t) => allowed.has(t.customerId) && t.productId === productId,
      );
      if (!match) throw new NotFoundException('未找到相关购买记录');
    }

    const product = await this.dynamodb.get(this.productTable, { productId });
    if (!product) throw new NotFoundException('产品不存在');
    return product;
  }

  async getTransactionDetail(
    transactionId: string,
    currentUser: { userId: string; role: string },
  ) {
    // 查询交易
    const txns = await this.dynamodb.scan(
      this.txnTable,
      '#tid = :tid',
      { ':tid': transactionId },
      { '#tid': 'transactionId' },
    );
    const txn = txns?.[0];
    if (!txn) throw new NotFoundException('交易不存在');

    // 权限校验：若有限定集合，则交易的 customerId 必须在集合中
    const allowed = await this.getAllowedCustomerIds(currentUser);
    if (allowed && !allowed.has(txn.customerId)) {
      throw new NotFoundException('交易不存在');
    }

    // 补充产品/客户名称
    const [product, customer] = await Promise.all([
      txn.productId
        ? this.dynamodb.get(this.productTable, { productId: txn.productId })
        : undefined,
      txn.customerId
        ? this.dynamodb.get(this.customerTable, { customerId: txn.customerId })
        : undefined,
    ]);
    const productName = product?.productName;
    const customerName = customer
      ? `${customer.lastName || ''}${customer.firstName || ''}`
      : undefined;

    return { ...txn, productName, customerName };
  }
}
