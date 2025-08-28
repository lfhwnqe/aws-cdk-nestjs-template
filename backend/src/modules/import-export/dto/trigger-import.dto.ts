import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class TriggerImportDto {
  @ApiProperty({ example: 'imports/customer/uuid-customers_2024-08-15.xlsx' })
  @IsString()
  @IsNotEmpty()
  key: string;
}
