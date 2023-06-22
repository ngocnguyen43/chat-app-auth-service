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
  public static LoginOptions = async (req: Request, res: Response, next: NextFunction) => {
    return res.status(200).json(await AuthService.LoginOptions(req.body.email as string));
  };
  public static LoginPassword = async (req: Request, res: Response, next: NextFunction) => {
    return res.status(200).json(await AuthService.LoginPassword(req.body as LogInDto));
  };
}
