import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsDateString,
  MinLength,
  MaxLength,
} from 'class-validator';

export class CommunicationRecordDto {
  @ApiProperty({
    description: '沟通记录ID',
    example: 'comm_1234567890',
  })
  @IsString({ message: '记录ID必须是字符串' })
  @IsNotEmpty({ message: '记录ID不能为空' })
  id: string;

  @ApiProperty({
    description: '沟通内容',
    example: '客户咨询理财产品相关信息',
  })
  @IsString({ message: '沟通内容必须是字符串' })
  @IsNotEmpty({ message: '沟通内容不能为空' })
  @MinLength(1, { message: '沟通内容至少需要1个字符' })
  @MaxLength(2000, { message: '沟通内容不能超过2000个字符' })
  content: string;

  @ApiProperty({
    description: '沟通类型',
    example: '电话',
    enum: ['电话', '邮件', '微信', '面谈', '短信', '其他'],
  })
  @IsString({ message: '沟通类型必须是字符串' })
  @IsNotEmpty({ message: '沟通类型不能为空' })
  type: string;

  @ApiProperty({
    description: '沟通时间',
    example: '2024-01-01T10:30:00.000Z',
  })
  @IsDateString({}, { message: '请输入有效的日期时间格式 (ISO 8601)' })
  @IsNotEmpty({ message: '沟通时间不能为空' })
  timestamp: string;

  @ApiProperty({
    description: '沟通人员（记录者）',
    example: '张三',
  })
  @IsString({ message: '记录者必须是字符串' })
  @IsNotEmpty({ message: '记录者不能为空' })
  @MinLength(1, { message: '记录者至少需要1个字符' })
  @MaxLength(50, { message: '记录者不能超过50个字符' })
  createdBy: string;

  @ApiProperty({
    description: '沟通结果或后续行动',
    example: '客户表示感兴趣，安排下次面谈',
    required: false,
  })
  @IsString({ message: '沟通结果必须是字符串' })
  @IsOptional()
  @MaxLength(1000, { message: '沟通结果不能超过1000个字符' })
  outcome?: string;
}
