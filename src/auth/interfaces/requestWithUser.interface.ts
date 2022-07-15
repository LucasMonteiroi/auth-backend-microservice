import User from '../../modules/users/entity/user.entity';

interface RequestWithUser extends Request {
  user: User;
}

export default RequestWithUser;
