import { ApiProperty } from '@nestjs/swagger';

export class ImportErrorDetail {
  @ApiProperty({
    description: '行号',
    example: 2,
  })
  row: number;

  @ApiProperty({
    description: '错误信息',
    example: '邮箱格式不正确',
  })
  error: string;

  @ApiProperty({
    description: '客户数据',
    example: {
      email: 'invalid-email',
      phone: '+86 138 0013 8000',
      firstName: '小明',
      lastName: '张',
    },
  })
  data: any;
}

export class ImportResultDto {
  @ApiProperty({
    description: '导入成功数量',
    example: 10,
  })
  successCount: number;

  @ApiProperty({
    description: '导入失败数量',
    example: 2,
  })
  failureCount: number;

  @ApiProperty({
    description: '跳过数量（重复数据）',
    example: 1,
  })
  skippedCount: number;

  @ApiProperty({
    description: '总处理数量',
    example: 13,
  })
  totalCount: number;

  @ApiProperty({
    description: '错误详情列表',
    type: [ImportErrorDetail],
  })
  errors: ImportErrorDetail[];

  @ApiProperty({
    description: '导入结果消息',
    example: '导入完成：成功 10 条，失败 2 条，跳过 1 条',
  })
  message: string;
}
