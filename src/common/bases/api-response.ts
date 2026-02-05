import { ApiResponeKey } from 'src/enum/api-response-key.enum';
import { HttpStatus } from '@nestjs/common';

export class ApiResponse<T = null> {
  [ApiResponeKey.STATUS]: boolean;
  [ApiResponeKey.CODE]: number;
  [ApiResponeKey.MESSAGE]: string;
  [ApiResponeKey.DATA]?: T;
  [ApiResponeKey.ERRORS]?: any;
  [ApiResponeKey.TIMESTAMP]: string;

  constructor(options: {
    status: boolean;
    code?: number;
    message: string;
    data?: T;
    errors?: any;
  }) {
    this.status = options.status;
    this.code = options.code ?? HttpStatus.OK;
    this.message = options.message;
    this.data = options.data;
    this.errors = options.errors;
    this.timestamp = new Date().toISOString();
  }
}

// ✅ Thành công – không có data
// return new ApiResponse({
//   status: true,
//   message: 'Tạo thành công',
// });

// ✅ Thành công – có data
// return new ApiResponse<UserDto>({
//   status: true,
//   message: 'Lấy user thành công',
//   data: user,
// });

// ✅ Thành công – danh sách
// return new ApiResponse<UserDto[]>({
//   status: true,
//   message: 'Danh sách user',
//   data: users,
// });

// ❌ Thất bại – không có data
// return new ApiResponse({
//   status: false,
//   code: HttpStatus.BAD_REQUEST,
//   message: 'Dữ liệu không hợp lệ',
// });

// ❌ Thất bại – có errors
// return new ApiResponse({
//   status: false,
//   code: HttpStatus.UNPROCESSABLE_ENTITY,
//   message: 'Validate lỗi',
//   errors: errors,
// });
