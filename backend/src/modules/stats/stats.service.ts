import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { DynamodbService } from '../../database/dynamodb.service';
import { TransactionStatus } from '../transaction/entities/transaction.entity';

export interface SummaryStats {
  totalCustomers: number;
  activeCustomers: number;
  customersWithoutTransactions: number;
  historicalSales: number;
  ongoingSales: number;
}

export interface HistoryEntry extends SummaryStats {
  date: string;
}

@Injectable()
export class StatsService {
  private readonly logger = new Logger(StatsService.name);
  private readonly customersTable: string;
  private readonly transactionsTable: string;

  constructor(
    private readonly dynamodbService: DynamodbService,
    private readonly configService: ConfigService,
  ) {
    this.customersTable = this.configService.get<string>(
      'database.tables.customers',
    );
    this.transactionsTable = this.configService.get<string>(
      'database.tables.customerProductTransactions',
    );
  }

  async getSummary(): Promise<SummaryStats> {
    const customers = await this.dynamodbService.scanAll(
      this.customersTable,
      undefined,
      undefined,
      'customerId',
    );

    const statuses = [
      TransactionStatus.PENDING,
      TransactionStatus.CONFIRMED,
      TransactionStatus.COMPLETED,
      TransactionStatus.CANCELLED,
    ];

    const transactions = (
      await Promise.all(
        statuses.map((status) =>
          this.dynamodbService.queryAll(
            this.transactionsTable,
            '#status = :status',
            { ':status': status },
            'TransactionStatusIndex',
            'transactionStatus,customerId,totalAmount,createdAt,completedAt',
            { '#status': 'transactionStatus' },
          ),
        ),
      )
    ).flat();

    const activeStatuses = [
      TransactionStatus.PENDING,
      TransactionStatus.CONFIRMED,
    ];

    const totalCustomers = customers.length;
    const customersWithTransactions = new Set(
      transactions.map((t) => t.customerId),
    );
    const activeCustomerIds = new Set(
      transactions
        .filter((t) => activeStatuses.includes(t.transactionStatus))
        .map((t) => t.customerId),
    );

    const activeCustomers = customers.filter((c) =>
      activeCustomerIds.has(c.customerId),
    ).length;
    const customersWithoutTransactions = customers.filter(
      (c) => !customersWithTransactions.has(c.customerId),
    ).length;

    const historicalSales = transactions
      .filter((t) => t.transactionStatus === TransactionStatus.COMPLETED)
      .reduce((sum, t) => sum + (t.totalAmount || 0), 0);

    const ongoingSales = transactions
      .filter((t) => activeStatuses.includes(t.transactionStatus))
      .reduce((sum, t) => sum + (t.totalAmount || 0), 0);

    return {
      totalCustomers,
      activeCustomers,
      customersWithoutTransactions,
      historicalSales,
      ongoingSales,
    };
  }

  private formatDate(dateStr: string, granularity: 'day' | 'month'): string {
    const date = new Date(dateStr);
    if (granularity === 'day') {
      return date.toISOString().slice(0, 10);
    }
    return date.toISOString().slice(0, 7);
  }

  async getHistory(
    granularity: 'day' | 'month' = 'month',
  ): Promise<HistoryEntry[]> {
    const customers = await this.dynamodbService.scanAll(
      this.customersTable,
      undefined,
      undefined,
      'customerId,createdAt',
    );

    const statuses = [
      TransactionStatus.PENDING,
      TransactionStatus.CONFIRMED,
      TransactionStatus.COMPLETED,
      TransactionStatus.CANCELLED,
    ];

    const transactions = (
      await Promise.all(
        statuses.map((status) =>
          this.dynamodbService.queryAll(
            this.transactionsTable,
            '#status = :status',
            { ':status': status },
            'TransactionStatusIndex',
            'transactionStatus,customerId,totalAmount,createdAt,completedAt',
            { '#status': 'transactionStatus' },
          ),
        ),
      )
    ).flat();

    const activeStatuses = [
      TransactionStatus.PENDING,
      TransactionStatus.CONFIRMED,
    ];

    const buckets: Record<string, HistoryEntry> = {};

    const getBucket = (date: string): HistoryEntry => {
      if (!buckets[date]) {
        buckets[date] = {
          date,
          totalCustomers: 0,
          activeCustomers: 0,
          customersWithoutTransactions: 0,
          historicalSales: 0,
          ongoingSales: 0,
        };
      }
      return buckets[date];
    };

    const transactionsByCustomer: Record<string, any[]> = {};
    for (const t of transactions) {
      if (!transactionsByCustomer[t.customerId]) {
        transactionsByCustomer[t.customerId] = [];
      }
      transactionsByCustomer[t.customerId].push(t);
    }

    for (const customer of customers) {
      const key = this.formatDate(customer.createdAt, granularity);
      const bucket = getBucket(key);
      bucket.totalCustomers += 1;

      const custTxns = transactionsByCustomer[customer.customerId] || [];
      if (custTxns.length === 0) {
        bucket.customersWithoutTransactions += 1;
      } else if (
        custTxns.some((t) => activeStatuses.includes(t.transactionStatus))
      ) {
        bucket.activeCustomers += 1;
      }
    }

    for (const t of transactions) {
      const key = this.formatDate(t.completedAt || t.createdAt, granularity);
      const bucket = getBucket(key);

      if (t.transactionStatus === TransactionStatus.COMPLETED) {
        bucket.historicalSales += t.totalAmount || 0;
      } else if (activeStatuses.includes(t.transactionStatus)) {
        bucket.ongoingSales += t.totalAmount || 0;
      }
    }

    return Object.values(buckets).sort((a, b) => a.date.localeCompare(b.date));
  }
}
