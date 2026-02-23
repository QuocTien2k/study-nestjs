import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { ApiResponse } from '../bases/api-response';

//api khi trả về cùng 1 structure do class ApiResponse
@Injectable()
export class ResponseInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      map((data) => {
        // Nếu controller đã return ApiResponse thì bỏ qua
        if (data instanceof ApiResponse) {
          return data;
        }

        //nếu không có giá trị trả về thì không gửi data
        if (data === undefined || data === null) {
          return new ApiResponse({
            status: true,
            message: 'SUCCESS',
          });
        }

        return new ApiResponse({
          status: true,
          message: 'SUCCESS',
          data,
        });
      }),
    );
  }
}
