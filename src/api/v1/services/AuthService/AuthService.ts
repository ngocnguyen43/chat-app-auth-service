import { LogInDto, RegistrationDto, userGoogleLoginDto } from '@v1/interface';
import { UserRepository, AuthOptionsRepository } from '../../repositories';
import { CREATED } from '../../utils';
import jwt, { UserJWTPayload } from 'jsonwebtoken';
import {
  GenerateRegistrationOptionsOpts,
  VerifiedRegistrationResponse,
  VerifyRegistrationResponseOpts,
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { Unexpected } from '../../repositories/exceptions';
declare module 'jsonwebtoken' {
  interface UserJWTPayload extends jwt.JwtPayload {
    iss: string;
    nbf: number;
    aud: string;
    sub: string;
    email: string;
    email_verified: boolean;
    azp: string;
    name: string;
    picture: string;
    given_name: string;
    family_name: string;
    iat: number;
    exp: number;
    jti: string;
  }
}
type ValidOption = [object[], string];
export default class AuthService {
  private static checkValidOption(value: ValidOption, federation: ValidOption) {
    return (
      value[0].some((item) => item.hasOwnProperty(value[1])) &&
      federation[0].some((item) => item.hasOwnProperty(federation[1]))
    );
  }
  public static Registration = async (user: RegistrationDto) => {
    const newUser = await UserRepository.createOne(user);
    await AuthOptionsRepository.AddPassword(newUser.id, user.password);
    return new CREATED();
  };
  public static GooglePopupLogin = async (user: userGoogleLoginDto) => {
    const userFound = await UserRepository.findOneByEmail(user.email);
    if (!userFound) {
      const newUser = await UserRepository.createOneFromGoogle(user);
      await AuthOptionsRepository.AddEmail(newUser.id, newUser.email);
      return { fullname: newUser.firstName + newUser.lastName, email: newUser.email };
    } else {
      const userGoogleFound = await AuthOptionsRepository.FindOneWithKeyValue(userFound.id, 'google', 'oauth');
      if (!userGoogleFound) {
        await AuthOptionsRepository.AddEmail(userFound.id, userFound.email);
        return { full_name: userFound.firstName + ' ' + userFound.lastName, email: userFound.email };
      }
      return { full_name: userFound.firstName + ' ' + userFound.lastName, email: userFound.email };
    }
  };
  public static OptionsLogin = async (email: string) => {
    const user = await UserRepository.findOneByEmail(email);
    const options = await AuthOptionsRepository.LoginOptions(user ? user.id : null);
    return options;
  };
  public static PasswordLogin = async (user: LogInDto) => {
    const userFound = await UserRepository.findOneByEmail(user.email);
    const result = await AuthOptionsRepository.LoginPassword(userFound.id || null, user.password);
    return result;
  };
  public static GoogleIdLogin = async (credential: string) => {
    const decoded = jwt.decode(credential) as UserJWTPayload;
    const userFound = await UserRepository.findOneByEmail(decoded['email']);
    if (!userFound) {
      const newUser = await UserRepository.createOne({
        firstName: decoded.family_name,
        lastName: decoded.given_name,
        email: decoded.email,
      });
      await AuthOptionsRepository.AddEmail(newUser.id, newUser.email, decoded.aud);
      return { fullname: newUser.firstName + newUser.lastName, email: newUser.email };
    }
    const option = await AuthOptionsRepository.FindOneWithKeyValue(userFound.id, 'google', 'oauth');
    if (option && this.checkValidOption([option.key['value'], 'google'], [option.key['federated'], 'google'])) {
      return { fullname: userFound.firstName + userFound.lastName, email: userFound.email };
    }
    await AuthOptionsRepository.AddEmail(userFound.id, userFound.email, decoded.aud);
    return { fullname: userFound.firstName + userFound.lastName, email: userFound.email };
  };
  public static WebAuthnRegistrationOptions = async (email: string) => {
    const user = await UserRepository.findOneByEmail(email);
    const authn = await AuthOptionsRepository.FindOneByUserId(user.id, 'passkey');
    if (!user) {
    }
    const options: GenerateRegistrationOptionsOpts = {
      rpName: 'Chat App',
      rpID: 'localhost',
      userID: user.email,
      userName: user.firstName + ' ' + user.lastName,
      timeout: 60000,
      attestationType: 'none',
      excludeCredentials: authn
        ? (authn.key['devices'] as []).map((dev: any) => ({
            id: dev.credentialID,
            type: 'public-key',
            transports: dev.transports,
          }))
        : [],
      authenticatorSelection: {
        userVerification: 'required',
        residentKey: 'required',
      },
      supportedAlgorithmIDs: [-7, -257],
    };
    const regOptions = generateRegistrationOptions(options);
    await AuthOptionsRepository.AddChallenge(user.id, regOptions.challenge);
    return regOptions;
  };
  public static WebAuthnRegistrationVerification = async (credential: any) => {
    const user = await UserRepository.findOneByEmail(credential['user']['email']);
    const auth = await AuthOptionsRepository.FindOneByUserId(user.id, 'passkey');
    const data = credential['data'];
    const expectedChallenge = user.currentChallenge;
    let verification: VerifiedRegistrationResponse;
    try {
      const options: VerifyRegistrationResponseOpts = {
        response: credential,
        expectedChallenge: `${expectedChallenge}`,
        expectedOrigin: 'http://localhost:5173',
        expectedRPID: 'localhost',
        requireUserVerification: true,
      };
      verification = await verifyRegistrationResponse(options);
    } catch (error) {
      console.log(error);
      throw new Unexpected();
    }
    const { verified, registrationInfo } = verification;
    if (verified && registrationInfo) {
      const { credentialPublicKey, credentialID, counter } = registrationInfo;
      const existingDevice = auth.key['devices']
        ? (auth.key['devices'] as []).find((device: any) => Buffer.from(device.credentialID.data).equals(credentialID))
        : false;
      if (!existingDevice) {
        const newDevice = {
          credentialPublicKey,
          credentialID,
          counter,
          transports: data.response.transports,
        };
        await AuthOptionsRepository.AddDevice(auth.id, user.id, newDevice);
      }
    }
    return { ok: true };
  };
  public static WebAuthnLoginOptions = async () => {};
  public static WebAuthnLoginVerification = async () => {};
}
