import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import {
  BadRequestException,
  UnsupportedMediaTypeException,
} from '@nestjs/common';
import { CustomerService } from './customer.service';
import { DynamodbService } from '../../database/dynamodb.service';
import { CustomerStatus, RiskLevel, IdType } from './entities/customer.entity';

describe('CustomerService - Excel Import/Export', () => {
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
      scan: jest.fn(),
      query: jest.fn(),
      put: jest.fn(),
      get: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
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

  describe('getAllCustomersForExport', () => {
    it('should return all customers sorted by creation time', async () => {
      const customers = [
        {
          ...mockCustomer,
          customerId: 'cust_2',
          createdAt: '2024-01-02T00:00:00.000Z',
        },
        {
          ...mockCustomer,
          customerId: 'cust_1',
          createdAt: '2024-01-01T00:00:00.000Z',
        },
      ];
      dynamodbService.scan.mockResolvedValue(customers);

      const result = await service.getAllCustomersForExport();

      expect(result).toHaveLength(2);
      expect(result[0].customerId).toBe('cust_1'); // 应该按创建时间排序
      expect(result[1].customerId).toBe('cust_2');
      expect(dynamodbService.scan).toHaveBeenCalledWith('customers');
    });

    it('should throw BadRequestException on database error', async () => {
      dynamodbService.scan.mockRejectedValue(new Error('Database error'));

      await expect(service.getAllCustomersForExport()).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('generateExcelBuffer', () => {
    it('should generate Excel buffer for customers', async () => {
      const customers = [mockCustomer];

      const result = await service.generateExcelBuffer(customers);

      expect(result).toBeInstanceOf(Buffer);
      expect(result.length).toBeGreaterThan(0);
    });

    it('should handle empty customer list', async () => {
      const result = await service.generateExcelBuffer([]);

      expect(result).toBeInstanceOf(Buffer);
      expect(result.length).toBeGreaterThan(0);
    });
  });

  describe('importCustomersFromExcel', () => {
    const mockFile: Express.Multer.File = {
      fieldname: 'file',
      originalname: 'customers.xlsx',
      encoding: '7bit',
      mimetype:
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      size: 1024,
      buffer: Buffer.from('mock excel data'),
      destination: '',
      filename: '',
      path: '',
      stream: null,
    };

    it('should throw BadRequestException if no file provided', async () => {
      await expect(service.importCustomersFromExcel(null)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should throw UnsupportedMediaTypeException for invalid file type', async () => {
      const invalidFile = { ...mockFile, mimetype: 'text/plain' };

      await expect(
        service.importCustomersFromExcel(invalidFile),
      ).rejects.toThrow(UnsupportedMediaTypeException);
    });
  });
});
