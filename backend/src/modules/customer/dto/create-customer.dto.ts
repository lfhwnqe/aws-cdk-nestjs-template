import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
  IsEmail,
  IsEnum,
  IsNotEmpty,
  IsOptional,
  MinLength,
  MaxLength,
  Matches,
  IsDateString,
  IsArray,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';
import { IdType, RiskLevel, CustomerStatus } from '../entities/customer.entity';
import { CommunicationRecord } from '../interfaces/communication-record.interface';
import { CommunicationRecordDto } from './communication-record.dto';

export class CreateCustomerDto {
  @ApiProperty({
    description: '邮箱地址',
    example: 'customer@example.com',
  })
  @IsEmail({}, { message: '请输入有效的邮箱地址' })
  @IsNotEmpty({ message: '邮箱地址不能为空' })
  email: string;

  @ApiProperty({
    description: '登录账号',
    example: 'customer01',
    required: false,
  })
  @IsString({ message: '登录账号必须是字符串' })
  @IsOptional()
  @MinLength(3, { message: '登录账号至少需要3个字符' })
  @MaxLength(30, { message: '登录账号不能超过30个字符' })
  username?: string;

  @ApiProperty({
    description: '登录密码',
    example: 'Password123!',
    required: false,
  })
  @IsString({ message: '登录密码必须是字符串' })
  @IsOptional()
  @MinLength(8, { message: '登录密码至少需要8个字符' })
  @Matches(/(?=.*[a-z])/, { message: '登录密码需至少包含一个小写字母' })
  @Matches(/(?=.*[A-Z])/, { message: '登录密码需至少包含一个大写字母' })
  @Matches(/(?=.*\d)/, { message: '登录密码需至少包含一个数字' })
  @Matches(/(?=.*[@$!%*?&])/, {
    message: '登录密码需至少包含一个特殊字符(@$!%*?&)',
  })
  password?: string;

  @ApiProperty({
    description: '手机号码',
    example: '+86 138 0013 8000',
  })
  @IsString({ message: '手机号码必须是字符串' })
  @IsNotEmpty({ message: '手机号码不能为空' })
  @Matches(/^(\+86\s?)?1[3-9]\d{9}$/, {
    message: '请输入有效的中国大陆手机号码',
  })
  phone: string;

  @ApiProperty({
    description: '名',
    example: '小明',
  })
  @IsString({ message: '名必须是字符串' })
  @IsNotEmpty({ message: '名不能为空' })
  @MinLength(1, { message: '名至少需要1个字符' })
  @MaxLength(50, { message: '名不能超过50个字符' })
  firstName: string;

  @ApiProperty({
    description: '姓',
    example: '张',
  })
  @IsString({ message: '姓必须是字符串' })
  @IsNotEmpty({ message: '姓不能为空' })
  @MinLength(1, { message: '姓至少需要1个字符' })
  @MaxLength(50, { message: '姓不能超过50个字符' })
  lastName: string;

  @ApiProperty({
    description: '身份证件类型',
    enum: IdType,
    example: IdType.ID_CARD,
  })
  @IsEnum(IdType, { message: '请选择有效的身份证件类型' })
  @IsNotEmpty({ message: '身份证件类型不能为空' })
  idType: IdType;

  @ApiProperty({
    description: '身份证件号码',
    example: '110101199001011234',
  })
  @IsString({ message: '身份证件号码必须是字符串' })
  @IsNotEmpty({ message: '身份证件号码不能为空' })
  @MinLength(6, { message: '身份证件号码至少需要6个字符' })
  @MaxLength(30, { message: '身份证件号码不能超过30个字符' })
  idNumber: string;

  @ApiProperty({
    description: '出生日期 (YYYY-MM-DD格式)',
    example: '1990-01-01',
  })
  @IsDateString({}, { message: '请输入有效的日期格式 (YYYY-MM-DD)' })
  @IsNotEmpty({ message: '出生日期不能为空' })
  dateOfBirth: string;

  @ApiProperty({
    description: '联系地址',
    example: '北京市朝阳区某某街道123号',
  })
  @IsString({ message: '联系地址必须是字符串' })
  @IsNotEmpty({ message: '联系地址不能为空' })
  @MinLength(5, { message: '联系地址至少需要5个字符' })
  @MaxLength(200, { message: '联系地址不能超过200个字符' })
  address: string;

  @ApiProperty({
    description: '风险承受等级',
    enum: RiskLevel,
    example: RiskLevel.MEDIUM,
  })
  @IsEnum(RiskLevel, { message: '请选择有效的风险承受等级' })
  @IsNotEmpty({ message: '风险承受等级不能为空' })
  riskLevel: RiskLevel;

  @ApiProperty({
    description: '客户状态',
    enum: CustomerStatus,
    example: CustomerStatus.ACTIVE,
    required: false,
  })
  @IsEnum(CustomerStatus, { message: '请选择有效的客户状态' })
  @IsOptional()
  status?: CustomerStatus = CustomerStatus.ACTIVE;

  @ApiProperty({
    description: '备注信息',
    example: '重要客户，需要特别关注',
    required: false,
  })
  @IsString({ message: '备注信息必须是字符串' })
  @IsOptional()
  @MaxLength(1000, { message: '备注信息不能超过1000个字符' })
  remarks?: string;

  @ApiProperty({
    description: '微信号',
    example: 'wechat_user123',
    required: false,
  })
  @IsString({ message: '微信号必须是字符串' })
  @IsOptional()
  @MinLength(1, { message: '微信号至少需要1个字符' })
  @MaxLength(50, { message: '微信号不能超过50个字符' })
  wechatId?: string;

  @ApiProperty({
    description: '沟通记录',
    type: 'array',
    items: {
      type: 'object',
      properties: {
        id: { type: 'string', description: '记录ID' },
        content: { type: 'string', description: '沟通内容' },
        type: { type: 'string', description: '沟通类型' },
        timestamp: { type: 'string', description: '沟通时间' },
        createdBy: { type: 'string', description: '记录者' },
        outcome: { type: 'string', description: '沟通结果' },
      },
    },
    required: false,
  })
  @IsArray({ message: '沟通记录必须是数组格式' })
  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => CommunicationRecordDto)
  communicationRecords?: CommunicationRecord[];
}
