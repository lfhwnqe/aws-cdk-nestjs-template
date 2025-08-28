import { PartialType } from '@nestjs/mapped-types';
import { CreateProductDto } from './create-product.dto';

// 更新时仅允许修改可变字段；主键/只读字段不应包含在 DTO 中
export class UpdateProductDto extends PartialType(CreateProductDto) {}
