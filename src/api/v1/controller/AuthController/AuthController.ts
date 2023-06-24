import { NextFunction, Request, Response } from 'express';
import AuthService from '../../services/AuthService/AuthService';
import { LogInDto, RegistrationDto, userGoogleLoginDto } from '@v1/interface';

export default class AuthController {
  public static registration = async (req: Request, res: Response, next: NextFunction) => {
    return res.status(201).json(await AuthService.Registration(req.body as RegistrationDto));
  };
  public static loginWithGoole = async (req: Request, res: Response, next: NextFunction) => {
    return res.status(200).json(await AuthService.GooglePopupLogin(req.body as userGoogleLoginDto));
  };
  public static loginWithIDGoole = async (req: Request, res: Response, next: NextFunction) => {
    return res.status(200).json(await AuthService.GoogleIdLogin(req.body.credential as string));
  };
  public static LoginOptions = async (req: Request, res: Response, next: NextFunction) => {
    return res.status(200).json(await AuthService.OptionsLogin(req.body.email as string));
  };
  public static LoginPassword = async (req: Request, res: Response, next: NextFunction) => {
    return res.status(200).json(await AuthService.PasswordLogin(req.body as LogInDto));
  };
  public static WebAuthnRegistrationOptions = async (req: Request, res: Response, next: NextFunction) => {
    return res.status(200).json(await AuthService.WebAuthnRegistrationOptions(req.body.email as string));
  };
  public static WebAuthnRegistrationVerification = async (req: Request, res: Response, next: NextFunction) => {
    return res.status(200).json(await AuthService.WebAuthnRegistrationVerification(req.body.data));
  };
  public static WebAuthnLoginOptions = async (req: Request, res: Response, next: NextFunction) => {
    return res.status(200).json(await AuthService.WebAuthnLoginOptions(req.body.email as string));
  };
  public static WebAuthnLoginVerification = async (req: Request, res: Response, next: NextFunction) => {
    return res.status(200).json(await AuthService.WebAuthnLoginVerification(req.body.email as string, req.body.data));
  };
  public static LoginWithFacebook;
  public static LoginWithGithub;
}
