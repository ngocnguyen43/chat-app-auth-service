import { NextFunction, Request, Response } from 'express';
import AuthService from '../../services/AuthService/AuthService';
import { RegistrationDto } from '@v1/interface';

export default class AuthController {
  public static registration = async (req: Request, res: Response, next: NextFunction) => {
    return res.status(201).json(await AuthService.Registration(req.body as RegistrationDto));
  };
}
