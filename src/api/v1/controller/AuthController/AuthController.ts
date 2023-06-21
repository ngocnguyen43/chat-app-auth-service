import { NextFunction, Request, Response } from 'express';
import AuthService from '../../services/AuthService/AuthService';
import { RegistrationDto, userGoogleLoginDto } from '@v1/interface';

export default class AuthController {
  public static registration = async (req: Request, res: Response, next: NextFunction) => {
    return res.status(201).json(await AuthService.Registration(req.body as RegistrationDto));
  };
  public static loginWithGoole = async (req: Request, res: Response, next: NextFunction) => {
    return res.status(201).json(await AuthService.GooglePopupLogin(req.body as userGoogleLoginDto));
  };
}
