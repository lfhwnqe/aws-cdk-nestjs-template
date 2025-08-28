import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import {
  NotFoundException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { CustomerService } from './customer.service';
import { DynamodbService } from '../../database/dynamodb.service';
import { CreateCustomerDto } from './dto/create-customer.dto';
import { UpdateCustomerDto } from './dto/update-customer.dto';
import { QueryCustomerDto } from './dto/query-customer.dto';
import { CustomerStatus, RiskLevel, IdType } from './entities/customer.entity';

describe('CustomerService', () => {
  let service: CustomerService;
  let dynamodbService: jest.Mocked<DynamodbService>;
  let configService: jest.Mocked<ConfigService>;

  const mockCustomer = {
    customerId: 'cust_test123',
    email: 'test@example.com',
    phone: '+86 138 0013 8000',
    firstName: '小明',
    lastName: '张',
    idType: IdType.ID_CARD,
    idNumber: '110101199001011234',
    dateOfBirth: '1990-01-01',
    address: '北京市朝阳区某某街道123号',
    riskLevel: RiskLevel.MEDIUM,
    status: CustomerStatus.ACTIVE,
    createdAt: '2024-01-01T00:00:00.000Z',
    updatedAt: '2024-01-01T00:00:00.000Z',
  };

  beforeEach(async () => {
    const mockDynamodbService = {
      put: jest.fn(),
      get: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      scan: jest.fn(),
      query: jest.fn(),
    };

    const mockConfigService = {
      get: jest.fn().mockReturnValue('customers'),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        CustomerService,
        {
          provide: DynamodbService,
          useValue: mockDynamodbService,
        },
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
      ],
    }).compile();

    service = module.get<CustomerService>(CustomerService);
    dynamodbService = module.get(DynamodbService);
    configService = module.get(ConfigService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('create', () => {
    const createCustomerDto: CreateCustomerDto = {
      email: 'test@example.com',
      phone: '+86 138 0013 8000',
      firstName: '小明',
      lastName: '张',
      idType: IdType.ID_CARD,
      idNumber: '110101199001011234',
      dateOfBirth: '1990-01-01',
      address: '北京市朝阳区某某街道123号',
      riskLevel: RiskLevel.MEDIUM,
      remarks: '测试客户备注',
      wechatId: 'test_wechat_123',
      communicationRecords: [
        {
          id: 'comm_test_001',
          content: '客户咨询产品信息',
          type: '电话',
          timestamp: '2024-01-01T10:00:00.000Z',
          createdBy: '测试员工',
          outcome: '客户表示感兴趣',
        },
      ],
    };

    it('should create a customer successfully', async () => {
      dynamodbService.query.mockResolvedValue([]); // 邮箱和手机号不存在
      dynamodbService.put.mockResolvedValue({});

      const result = await service.create(createCustomerDto);

      expect(result).toMatchObject({
        email: createCustomerDto.email,
        phone: createCustomerDto.phone,
        firstName: createCustomerDto.firstName,
        lastName: createCustomerDto.lastName,
        status: CustomerStatus.ACTIVE,
      });
      expect(result.customerId).toMatch(/^cust_/);
      expect(result.createdAt).toBeDefined();
      expect(result.updatedAt).toBeDefined();
      expect(dynamodbService.put).toHaveBeenCalledWith(
        'customers',
        expect.any(Object),
      );
    });

    it('should throw ConflictException if email already exists', async () => {
      dynamodbService.query.mockResolvedValueOnce([mockCustomer]); // 邮箱已存在

      await expect(service.create(createCustomerDto)).rejects.toThrow(
        ConflictException,
      );
    });

    it('should throw ConflictException if phone already exists', async () => {
      dynamodbService.query
        .mockResolvedValueOnce([]) // 邮箱不存在
        .mockResolvedValueOnce([mockCustomer]); // 手机号已存在

      await expect(service.create(createCustomerDto)).rejects.toThrow(
        ConflictException,
      );
    });
  });

  describe('findOne', () => {
    it('should return a customer if found', async () => {
      dynamodbService.get.mockResolvedValue(mockCustomer);

      const result = await service.findOne('cust_test123');

      expect(result).toEqual(mockCustomer);
      expect(dynamodbService.get).toHaveBeenCalledWith('customers', {
        customerId: 'cust_test123',
      });
    });

    it('should throw NotFoundException if customer not found', async () => {
      dynamodbService.get.mockResolvedValue(null);

      await expect(service.findOne('nonexistent')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('findByEmail', () => {
    it('should return a customer if found by email', async () => {
      dynamodbService.query.mockResolvedValue([mockCustomer]);

      const result = await service.findByEmail('test@example.com');

      expect(result).toEqual(mockCustomer);
      expect(dynamodbService.query).toHaveBeenCalledWith(
        'customers',
        'email = :email',
        { ':email': 'test@example.com' },
        'EmailIndex',
      );
    });

    it('should throw NotFoundException if customer not found by email', async () => {
      dynamodbService.query.mockResolvedValue([]);

      await expect(
        service.findByEmail('nonexistent@example.com'),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('findByPhone', () => {
    it('should return a customer if found by phone', async () => {
      dynamodbService.query.mockResolvedValue([mockCustomer]);

      const result = await service.findByPhone('+86 138 0013 8000');

      expect(result).toEqual(mockCustomer);
      expect(dynamodbService.query).toHaveBeenCalledWith(
        'customers',
        'phone = :phone',
        { ':phone': '+86 138 0013 8000' },
        'PhoneIndex',
      );
    });

    it('should throw NotFoundException if customer not found by phone', async () => {
      dynamodbService.query.mockResolvedValue([]);

      await expect(service.findByPhone('+86 138 0000 0000')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('update', () => {
    const updateCustomerDto: UpdateCustomerDto = {
      firstName: '小红',
      riskLevel: RiskLevel.HIGH,
      remarks: '更新的客户备注',
      wechatId: 'updated_wechat_123',
      communicationRecords: [
        {
          id: 'comm_test_002',
          content: '客户确认购买产品',
          type: '面谈',
          timestamp: '2024-01-02T14:00:00.000Z',
          createdBy: '销售经理',
          outcome: '成功签约',
        },
      ],
    };

    it('should update a customer successfully', async () => {
      dynamodbService.get.mockResolvedValue(mockCustomer);
      dynamodbService.update.mockResolvedValue({
        ...mockCustomer,
        ...updateCustomerDto,
      });

      const result = await service.update('cust_test123', updateCustomerDto);

      expect(result.firstName).toBe('小红');
      expect(result.riskLevel).toBe(RiskLevel.HIGH);
      expect(dynamodbService.update).toHaveBeenCalled();
    });

    it('should throw NotFoundException if customer not found', async () => {
      dynamodbService.get.mockResolvedValue(null);

      await expect(
        service.update('nonexistent', updateCustomerDto),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('remove', () => {
    it('should delete a customer successfully', async () => {
      dynamodbService.get.mockResolvedValue(mockCustomer);
      dynamodbService.delete.mockResolvedValue({});

      const result = await service.remove('cust_test123');

      expect(result).toEqual({ message: '客户删除成功' });
      expect(dynamodbService.delete).toHaveBeenCalledWith('customers', {
        customerId: 'cust_test123',
      });
    });

    it('should throw NotFoundException if customer not found', async () => {
      dynamodbService.get.mockResolvedValue(null);

      await expect(service.remove('nonexistent')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('findAll', () => {
    const queryDto: QueryCustomerDto = {
      page: 1,
      limit: 10,
    };

    it('should return paginated customer list', async () => {
      const customers = [mockCustomer];
      dynamodbService.scan.mockResolvedValue(customers);

      const result = await service.findAll(queryDto);

      expect(result).toEqual({
        data: customers,
        total: 1,
        page: 1,
        limit: 10,
        totalPages: 1,
      });
    });

    it('should filter customers by status', async () => {
      const customers = [mockCustomer];
      dynamodbService.scan.mockResolvedValue(customers);

      const queryWithStatus: QueryCustomerDto = {
        ...queryDto,
        status: CustomerStatus.ACTIVE,
      };

      await service.findAll(queryWithStatus);

      expect(dynamodbService.scan).toHaveBeenCalledWith(
        'customers',
        '#status = :status',
        { ':status': CustomerStatus.ACTIVE },
      );
    });
  });
});
