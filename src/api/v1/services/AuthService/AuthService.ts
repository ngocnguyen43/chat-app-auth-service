import { LogInDto, RegistrationDto, userGoogleLoginDto } from '@v1/interface';
import { UserRepository, AuthOptionsRepository } from '../../repositories';
import { CREATED } from '../../utils';
import jwt, { UserJWTPayload } from 'jsonwebtoken';
import {
  GenerateAuthenticationOptionsOpts,
  GenerateRegistrationOptionsOpts,
  VerifiedRegistrationResponse,
  VerifyRegistrationResponseOpts,
  generateAuthenticationOptions,
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
    await UserRepository.AddChallenge(user.id, regOptions.challenge);
    return regOptions;
  };
  public static WebAuthnRegistrationVerification = async (credential: any) => {
    try {
      const user = await UserRepository.findOneByEmail(credential['user']['email']);
      const auth = await AuthOptionsRepository.FindOneByUserId(user.id, 'passkey');
      const data = credential['loginRes'];
      console.log(data);
      const expectedChallenge = user.currentChallenge;
      let verification: VerifiedRegistrationResponse;
      const options = {
        response: data,
        expectedChallenge: `${expectedChallenge}`,
        expectedOrigin: 'http://localhost:5173',
        expectedRPID: 'localhost',
        requireUserVerification: true,
      };
      verification = await verifyRegistrationResponse(options);
      const { verified, registrationInfo } = verification;
      if (verified && registrationInfo) {
        const { credentialPublicKey, credentialID, counter } = registrationInfo;
        const existingDevice = auth
          ? (auth.key['devices'] as []).find((device: any) => Buffer.from(device.credentialID).equals(credentialID))
          : false;
        if (!auth) {
          const newDevice = {
            credentialPublicKey: Array.from(credentialPublicKey),
            credentialID: Array.from(credentialID),
            counter,
            transports: data.response.transports,
          };
          await AuthOptionsRepository.CreateDevice(user.id, newDevice);
          console.log(newDevice);
        }
        if (!existingDevice) {
          const newDevice = {
            credentialPublicKey: Array.from(credentialPublicKey),
            credentialID: Array.from(credentialID),
            counter,
            transports: data.response.transports,
          };
          await AuthOptionsRepository.AddDevice(auth.id, user.id, newDevice);
          console.log(newDevice);
        }
      }
      return { ok: true };
    } catch (error) {
      console.log(error);
      throw new Unexpected();
    }
  };
  public static WebAuthnLoginOptions = async (email: string) => {
    const user = await UserRepository.findOneByEmail(email);
    const authn = await AuthOptionsRepository.FindOneByUserId(user.id, 'passkey');
    const options: GenerateAuthenticationOptionsOpts = {
      timeout: 60000,
      allowCredentials: authn
        ? (authn.key['devices'] as []).map((device: any) => ({
            id: device.credentialID,
            type: 'public-key',
            // Optional
            transports: device.transports,
          }))
        : [],
      // devices:
      //   user && authn && authn.key['devices']
      //     ? authn.key['devices'].map((dev) => ({
      //         id: dev.credentialID,
      //         type: 'public-key',
      //         transports: dev.transports,
      //       }))
      //     : [],
      userVerification: 'required',
      rpID: 'localhost',
    };
    const loginOpts = generateAuthenticationOptions(options);
    const challenge = loginOpts.challenge;
    await UserRepository.AddChallenge(user.id, challenge);
    return loginOpts;
  };
  public static WebAuthnLoginVerification = async () => {};
}
