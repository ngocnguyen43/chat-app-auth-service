import { LogInDto, RegistrationDto, userGoogleLoginDto } from '@v1/interface';
import { UserRepository, AuthOptionsRepository } from '../../repositories';
import { CREATED, Options } from '../../utils';

export default class AuthService {
  public static async logIn(user: LogInDto) {}
  public static async Registration(user: RegistrationDto) {
    const newUser = await UserRepository.createOne(user);
    await AuthOptionsRepository.AddPassword(newUser.id, user.password);
    return new CREATED();
  }
  public static async GooglePopupLogin(user: userGoogleLoginDto) {
    const newUser = await UserRepository.createOneFromGoogle(user);
    await AuthOptionsRepository.AddEmail(newUser.id, newUser.email);
    return { fullname: newUser.firstName + newUser.lastName, email: newUser.email };
  }
  public static LoginOptions = async (email: string) => {
    const user = await UserRepository.findOneByEmail(email);
    const options = await AuthOptionsRepository.LoginOptions(user ? user.id : null);
    return options;
  };
  public static LoginPassword = async (user: LogInDto) => {
    const userFound = await UserRepository.findOneByEmail(user.email);
    const result = await AuthOptionsRepository.LoginPassword(userFound.id || null, user.password);
    return result;
  };
}
