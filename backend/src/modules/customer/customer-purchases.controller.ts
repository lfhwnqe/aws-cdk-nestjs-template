import { Controller, Get, Param, Query, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiTags,
} from '@nestjs/swagger';
import { RolesGuard } from '@/auth/guards/roles.guard';
import { Roles, Role } from '@/common/decorators/roles.decorator';
import { CurrentUser } from '@/common/decorators/current-user.decorator';
import { CustomerPurchasesService } from './customer-purchases.service';
import {
  QueryCustomerPurchasesDto,
  CustomerPurchaseListResponse,
} from './dto/query-customer-purchases.dto';

@ApiTags('Customer Purchases')
@ApiBearerAuth('JWT-auth')
@UseGuards(RolesGuard)
@Controller('customers')
export class CustomerPurchasesController {
  constructor(private readonly service: CustomerPurchasesService) {}

  @Get('purchases')
  @Roles(Role.SUPER_ADMIN, Role.ADMIN, Role.USER, Role.CUSTOMER)
  @ApiOperation({ summary: '客户购买的产品记录（分页）' })
  @ApiQuery({ name: 'page', required: false, example: 1 })
  @ApiQuery({ name: 'limit', required: false, example: 10 })
  @ApiQuery({ name: 'productId', required: false, description: '按产品ID筛选' })
  listPurchases(
    @Query() query: QueryCustomerPurchasesDto,
    @CurrentUser() user: any,
  ): Promise<CustomerPurchaseListResponse> {
    return this.service.listPurchases(query, {
      userId: user.userId,
      role: user.role,
    });
  }

  @Get('transactions/detail')
  @Roles(Role.SUPER_ADMIN, Role.ADMIN, Role.USER, Role.CUSTOMER)
  @ApiOperation({ summary: '根据交易ID查看交易详情（按权限）' })
  @ApiQuery({ name: 'transactionId', description: '交易ID', required: true })
  transactionDetail(
    @Query('transactionId') transactionId: string,
    @CurrentUser() user: any,
  ) {
    return this.service.getTransactionDetail(transactionId, {
      userId: user.userId,
      role: user.role,
    });
  }
}
