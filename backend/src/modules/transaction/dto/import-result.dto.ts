import { ApiProperty } from '@nestjs/swagger';

export class ImportErrorDetail {
  @ApiProperty({ description: '行号', example: 2 })
  row: number;

  @ApiProperty({ description: '错误信息', example: '数据格式错误' })
  error: string;

  @ApiProperty({ description: '行数据' })
  data: any;
}

export class ImportResultDto {
  @ApiProperty({ description: '导入成功数量' })
  successCount: number;

  @ApiProperty({ description: '导入失败数量' })
  failureCount: number;

  @ApiProperty({ description: '跳过数量' })
  skippedCount: number;

  @ApiProperty({ description: '总数量' })
  totalCount: number;

  @ApiProperty({ description: '错误列表', type: [ImportErrorDetail] })
  errors: ImportErrorDetail[];

  @ApiProperty({ description: '结果消息' })
  message: string;
}
