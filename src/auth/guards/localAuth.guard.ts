import {
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {
  handleRequest(err, user, info, context, status) {
    const request = context.switchToHttp().getRequest();
    user = request.body;
    if (!user.id) {
      throw new HttpException(
        { message: 'Missing id' },
        HttpStatus.BAD_REQUEST,
      );
    } else if (!user.email) {
      throw new HttpException(
        { message: 'Missing email' },
        HttpStatus.BAD_REQUEST,
      );
    }

    if (err) {
      throw err || new UnauthorizedException();
    }
    return user;
  }
}
