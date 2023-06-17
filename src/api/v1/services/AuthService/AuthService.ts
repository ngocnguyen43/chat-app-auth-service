import { RegistrationDto } from '@v1/interface';
import { UserRepository } from '../../repositories';
import { UserAlreadyExists } from './exceptions';

export default class AuthService {
  public static async logIn() {}
  public static async Registration(user: RegistrationDto) {
    const userFound = UserRepository.findOneByEmail(user.email);
    if (userFound) {
      throw new UserAlreadyExists();
    }
  }
}
