import { Request, Response } from 'express';
import { inject } from 'inversify';
import { controller, httpGet, httpPost, request, requestBody, response } from 'inversify-express-utils';

import { RabbitMQClient } from '../../../message-broker';
import { IAuhtService } from '../service/auth.service';
import { FacebookUserType, GithubUserType, GoogleUserType, StrictUnion, TYPES } from '../@types';
import { randomUUID } from 'crypto';
import { Middlewares, RequestValidator } from '../middleware';
import {
  ILoginOptionsDto,
  IPasswordLoginDto,
  IWebAuthnLoginOptions,
  IWebAuthnLoginVerification,
  IWebAuthnRegisterOptions,
} from '@v1';
import { container } from '../../../container';
import { IMessageExecute } from '../../../message-broker/MessageExecute';
import { config } from '../../../config';
import { passportGoogle } from '../oauth2/google';
import { passportGithub } from '../oauth2/github';
import { passportFacebook } from '../oauth2/facebook';
import { WrongCredentials } from '../../../libs/base-exception';
import { encrypt } from '../../../utils';
export interface RegisterDto {
  userId: string;
  email: string;
  userName: string;
  fullName: string;
  password: string;
  createdAt: string;
  updatedAt: string;
}
function extractValue(str: string, key: string) {
  const regex = new RegExp(`${key}=([^&]+)`);
  const match = regex.exec(str);
  return match ? match[1] : null;
}
@controller('/api/v1/auth')
export class AuthController {
  private rabbitMq = RabbitMQClient;
  constructor(@inject(TYPES.AuthService) private readonly _service: IAuhtService) { }
  @httpPost('/register', ...Middlewares.postRegisterCheck, RequestValidator)
  async Register(@request() req: Request, @requestBody() dto: RegisterDto, @response() res: Response) {
    dto.userId = randomUUID();
    const result = await this._service.Registration(dto)
    return res.cookie('token', result['refreshToken']).json({
      ok: 'ok',
      id: result['res']['userId'],
      email: result['res']['email'],
      full_name: result['res']['fullName'],
      user_name: result['res']['userName'],
      access_token: result['accessToken'],
    });
  }
  @httpPost('/login-options')
  async LoginOptions(@requestBody() dto: ILoginOptionsDto, @response() res: Response) {
    return res.json(await this._service.LoginOptions(dto.email));
  }
  @httpPost('/login-password')
  async LoginPassword(@requestBody() dto: IPasswordLoginDto, @request() req: Request, @response() res: Response) {
    const result = await this._service.PasswordLogin(dto);
    return res.cookie('rft', result['refreshToken'], { sameSite: "strict", httpOnly: true, secure: process.env.NODE_ENV === "production", domain: config["COOKIES_DOMAIN"], maxAge: 2 * 60 * 60 * 1000 }).json({
      id: result['res']['userId'],
      email: result['res']['email'],
      full_name: result['res']['fullName'],
      user_name: result['res']['userName'],
      access_token: result['accessToken'],
    });
  }
  @httpPost('/webauth-registration-options')
  async WebAuthnRegistrationOptions(@requestBody() dto: IWebAuthnRegisterOptions, @response() res: Response) {
    console.log(dto);
    return res.json(await this._service.WebAuthnRegistrationOptions(dto.email));
  }
  @httpPost('/webauth-registration-verification')
  async WebAuthnRegistrationVerification(@requestBody() dto: any, @response() res: Response) {
    console.log(dto);
    return res.json(await this._service.WebAuthnRegistrationVerification(dto['data']));
  }
  @httpPost('/webauth-login-options')
  async WebAuthnLoginOptions(@requestBody() dto: IWebAuthnLoginOptions, @response() res: Response) {
    return res.json(await this._service.WebAuthnLoginOptions(dto.email));
  }
  @httpPost('/webauth-login-verification')
  async WebAuthnLoginVerification(@requestBody() dto: IWebAuthnLoginVerification, @response() res: Response) {
    console.log(dto.email);
    return res.json(await this._service.WebAuthnLoginVerification(dto.email, dto.data));
  }
  @httpGet('/test')
  async Test(@response() res: Response) {
    const result = await RabbitMQClient.clientProduce('user-queue', {
      type: 'get-user-by-email',
      payload: {
        email: 'test1@gmail.com',
      },
    });
    return res.json(result);
  }
  @httpGet('/testfn')
  async Testfn(@request() req: Request, @response() res: Response) {
    // const resp = await this._service.GetPublicKeyFromUserId('212fd513-a02c-475c-9a76-b461303f8819');
    // const resp = await container
    //   .get<IMessageExecute>(TYPES.MessageExecute)
    //   .noResponseExecute('get-user-by-email', '212fd513-a02c-475c-9a76-b461303f8819');
    // const users = await this._service.Test();
    await this._service.TestCnt();
    return res.json({ msg: "OK" });
  }
  @httpPost('/refresh-token')
  async RefreshToken(@request() req: Request, @response() res: Response) {
    return res.json(
      await this._service.RefreshToken(req.body['email'] as string, req.headers['x-refresh-token'] as string),
    );
  }
  // @httpGet("/oauth-request")
  // async GetUrlOauth(@queryParam("mode") mode: "google" | "facebook" | "github", @response() res: Response) {
  //   const queriesParams = new URLSearchParams({
  //     client_id: config["GOOGLE_CLIENT_ID"],

  //     redirect_uri: "http://localhost:5173",

  //     response_type: 'code',

  //     scope: 'openid profile email',

  //     access_type: 'offline',

  //     state: 'standard_oauth',

  //     prompt: 'consent',

  //   }
  //   )
  //   const redirectUrl = "http://localhost:80/api/v1/auth/oauth2"
  //   const oAuth2Client = new OAuth2Client(
  //     config["GOOGLE_CLIENT_ID"],
  //     config["GOOGLE_CLIENT_SECRET"],
  //     redirectUrl,
  //   )
  //   const authorizedUrl = oAuth2Client.generateAuthUrl({
  //     access_type: "offline",
  //     scope: 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email openid ',
  //     prompt: "consent"
  //   })
  //   return res.json({
  //     url: authorizedUrl
  //   })
  // }
  @httpGet("/oauth-request", passportGoogle.authenticate("google", {
    scope: ["profile", "email"],
    // failureMessage: "lol",
    // failureRedirect: "http://localhost:5173",
    // successRedirect: "https://localhost:5173"
  }))
  @httpGet("/oauth2", passportGoogle.authenticate("google", {
    failureRedirect: config["ORIGIN"] + "/signin",
    session: false,
  }))
  async TestPCB(@request() req: Request, @response() res: Response) {
    // console.log(req["_passport"]["instance"]["_strategies"]["google"])
    const user = req.user as GoogleUserType
    console.log(user);

    await this._service.HandleCredential(user)
    const ssid = encrypt(user.sub)
    res.cookie("_s", ssid, { sameSite: "strict", httpOnly: true, secure: process.env.NODE_ENV === "production", domain: config["COOKIES_DOMAIN"], maxAge: 3 * 60 * 1000 })
    res.cookie("_avt", user.picture, { sameSite: "strict", httpOnly: true, secure: process.env.NODE_ENV === "production", domain: config["COOKIES_DOMAIN"], maxAge: 3 * 60 * 1000 })
    res.cookie("_p", "google", { sameSite: "strict", httpOnly: true, secure: process.env.NODE_ENV === "production", domain: config["COOKIES_DOMAIN"], maxAge: 3 * 60 * 1000 })
    res.cookie("_e", user.email ?? "", { sameSite: "strict", httpOnly: true, secure: process.env.NODE_ENV === "production", domain: config["COOKIES_DOMAIN"], maxAge: 3 * 60 * 1000 })

    // {
    //   sub: '102323097327899576439',
    //   name: 'Nguyên Hoàng',
    //   given_name: 'Nguyên',
    //   family_name: 'Hoàng',
    //   picture: 'https://lh3.googleusercontent.com/a/ACg8ocKUd_44W1ahtqgRa5SG9G0wlGbJS1TvNcrRtAsViTv1=s96-c',
    //   email: 'hoangnguyen403.2003@gmail.com',
    //   email_verified: true,
    //   locale: 'vi'
    // }
    const url = process.env.NODE_ENV === "production" ? "https://" + config["ORIGIN"] + "/setup" : config["ORIGIN"] + "/setup"
    res.redirect(url)
  }

  @httpGet("/oauth-request-github", passportGithub.authenticate("github", { scope: ['user:email'] }))
  async OauthGithub() { }
  @httpGet("/oauth2-github", passportGithub.authenticate("github"))
  async OauthGithubCb(@request() req: Request, @response() res: Response) {
    const user = req.user as GithubUserType
    // const uri = "name=" + encodeURIComponent(user.displayName) + "&email=" + encodeURIComponent(user.em)
    // console.log((uri));
    // res.cookie("alo", "Hello", { maxAge: 60 * 1000 })
    // res.redirect(config["ORIGIN"] + "/setup?" + uri)
    // console.log(user)
    // await this._service.HandleCredential(user)
    res.redirect(config["ORIGIN"] + "/setup")
  }
  @httpGet("/oauth-request-facebook", passportFacebook.authenticate("facebook"))
  async OauthFacebookb() { }
  @httpGet("/oauth2-facebook", passportFacebook.authenticate("facebook"))
  async OauthFacebookCb(@request() req: Request, @response() res: Response) {
    const user = req.user
    // const uri = "name=" + encodeURIComponent(user.displayName) + "&email=" + encodeURIComponent(user.em)
    // console.log((uri));
    // res.cookie("alo", "Hello", { maxAge: 60 * 1000 })
    // res.redirect(config["ORIGIN"] + "/setup?" + uri)
    console.log(user)
    res.redirect(config["ORIGIN"] + "/setup")
  }
  @httpGet("/login/success")
  async LoginSuccess(@request() req: Request, @response() resp: Response) {
    const data = req.headers.cookie.split("; ")
    let avtValue = null;
    let sValue = null
    let pValue = null
    let eValue = null
    for (const item of data) {
      avtValue = extractValue(item, "_avt");
      if (avtValue !== null) {
        break;
      }
    }
    for (const item of data) {
      sValue = extractValue(item, "_s");
      if (sValue !== null) {
        break;
      }
    }
    for (const item of data) {
      pValue = extractValue(item, "_p");
      if (pValue !== null) {
        break;
      }
    }
    for (const item of data) {
      eValue = extractValue(item, "_e");
      if (eValue !== null) {
        break;
      }
    }

    // if (!req.user) {
    //   throw new WrongCredentials()
    // }
    console.log(decodeURIComponent(eValue))
    const res = await this._service.HandleSetupCredential(sValue, pValue, eValue)
    // return {...res,}
    resp.clearCookie("_p").clearCookie("_e").clearCookie("_s").clearCookie("_avt")
    // const resp = await this._service.HandleCredential(req.user as StrictUnion<GoogleUserType | GithubUserType | FacebookUserType>)
    return resp.cookie('rft', resp['refreshToken'], { sameSite: "strict", httpOnly: true, secure: process.env.NODE_ENV === "production", domain: config["COOKIES_DOMAIN"], maxAge: 2 * 60 * 60 * 1000 }).json({
      isLoginBefore: res.isLoginBefore,
      id: res['id'],
      picture: avtValue,
      email: res['email'],
      full_name: res['fullName'],
      user_name: res['userName'],
      access_token: res['accessToken'],
      provider: res["provider"]
    });
  }
  @httpPost("/logout")
  async Logout(@response() res: Response) {
    // await this._service.TestCnt();
    res.clearCookie("rft");
  }
  @httpPost("/update-status")
  async UpdateStatusCode(@request() req: Request, @requestBody() body: { provider: string }, @response() res: Response) {
    const { provider } = body
    const id = req.header["x-id"]
    await this._service.UpdateStatusLogin(id, provider)
  }
  // @httpGet("/oauth2")
  // async GetData(@request() req: Request, @response() res: Response) {
  //   // console.log(req.query["code"])
  //   const code = req.query["code"]
  //   const redirectUrl = "http://localhost:80/api/v1/auth/oauth2"
  //   const oAuth2Client = new OAuth2Client(
  //     config["GOOGLE_CLIENT_ID"],
  //     config["GOOGLE_CLIENT_SECRET"],
  //     redirectUrl,
  //   )
  //   const r = await oAuth2Client.getToken(code as string);
  //   // oAuth2Client.setCredentials(r.tokens)

  //   console.log(r.tokens.access_token)
  //   // const ACT = oAuth2Client.credentials.access_token
  //   const response = await axios.get(`https://www.googleapis.com/oauth2/v3/userinfo?access_token=${r.tokens.access_token}`);
  //   console.log(response.data);

  //   res.redirect("http://localhost:5173/setup?email")
  // }
}
