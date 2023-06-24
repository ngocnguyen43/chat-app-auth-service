import { Router } from 'express';
import { ErrorHandler } from '../utils';
import { AuthController } from '../controller';

export const router = Router();
router.post('/auth/register', ErrorHandler(AuthController.registration));
router.post('/auth/login-google', ErrorHandler(AuthController.loginWithGoole));
router.post('/auth/login-options', ErrorHandler(AuthController.LoginOptions));
router.post('/auth/login-password', ErrorHandler(AuthController.LoginPassword));
router.post('/auth/login-google-id', ErrorHandler(AuthController.loginWithIDGoole));
router.post('/auth/webauth-registration-options', ErrorHandler(AuthController.WebAuthnRegistrationOptions));
router.post('/auth/webauth-registration-verification', ErrorHandler(AuthController.WebAuthnRegistrationVerification));
router.post('/auth/webauth-login-options', ErrorHandler(AuthController.WebAuthnLoginOptions));
router.post('/auth/webauth-login-verification', ErrorHandler(AuthController.WebAuthnLoginVerification));
