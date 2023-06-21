import { Router } from 'express';
import { ErrorHandler } from '../utils';
import { AuthController } from '../controller';

export const router = Router();
router.post('/auth/register', ErrorHandler(AuthController.registration));
