import { PipeTransform, Injectable, BadRequestException } from '@nestjs/common';
import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';

@Injectable()
export class ValidationPipe implements PipeTransform {
  async transform(value: any, { metatype }: any) {
    if (!metatype || !this.toValidate(metatype)) {
      return value;
    }

    const object = plainToInstance(metatype, value);

    const errors = await validate(object, {
      whitelist: true,
      forbidNonWhitelisted: true,
    });

    if (errors.length > 0) {
      // const formattedErrors = errors.flatMap((err) =>
      //   Object.values(err.constraints ?? {}).map((code) => ({
      //     field: err.property,
      //     code,
      //   })),
      // );

      const formattedErrors = errors.map((err) => {
        const constraints = err.constraints ?? {};

        // Ưu tiên REQUIRED nếu có
        if (constraints.isNotEmpty) {
          return {
            field: err.property,
            code: constraints.isNotEmpty,
          };
        }

        // Nếu không có REQUIRED thì lấy lỗi đầu tiên
        const firstConstraint = Object.values(constraints)[0];

        return {
          field: err.property,
          code: firstConstraint,
        };
      });

      throw new BadRequestException({
        message: 'VALIDATION_FAILED',
        errors: formattedErrors,
      });
    }

    return object;
  }

  private toValidate(metatype: Function): boolean {
    const types: Function[] = [String, Boolean, Number, Array, Object];
    return !types.includes(metatype);
  }
}
