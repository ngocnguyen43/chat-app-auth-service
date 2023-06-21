import { RegistrationDto } from '@v1/interface';
import { UserRepository } from '../../repositories';
import { Unexpected, UserAlreadyExists } from './exceptions';
import AuthOptionsRepository from '../../repositories/AuthOptionsRepository';
import { CREATED } from '../../utils';

export default class AuthService {
  public static async logIn() {}
  public static async Registration(user: RegistrationDto) {
    const userFound = await UserRepository.findOneByEmail(user.email);
    if (userFound) {
      throw new UserAlreadyExists();
    }
    try {
      const newUser = await UserRepository.createOne(user);
      await AuthOptionsRepository.AddPassword(newUser.id, user.password);
      return new CREATED();
    } catch (error) {
      console.log(error);
      throw new Unexpected();
    }
  }
}
