import { RegistrationDto, userGoogleLoginDto } from '@v1/interface';
import { UserRepository, AuthOptionsRepository } from '../../repositories';
import { CREATED } from '../../utils';

export default class AuthService {
  public static async logIn() {}
  public static async Registration(user: RegistrationDto) {
    const newUser = await UserRepository.createOne(user);
    await AuthOptionsRepository.AddPassword(newUser.id, user.password);
    return new CREATED();
  }
  public static async GooglePopupLogin(user: userGoogleLoginDto) {
    const newUser = await UserRepository.createOneFromGoogle(user);
    await AuthOptionsRepository.AddEmail(newUser.id, newUser.email);
    return new CREATED();
  }
}
