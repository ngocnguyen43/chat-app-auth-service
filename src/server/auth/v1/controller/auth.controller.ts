import { Request, Response } from 'express';
import { inject } from 'inversify';
import { controller, httpDelete, httpGet, httpPatch, httpPost, httpPut, queryParam, request, requestBody, response } from 'inversify-express-utils';

import { RabbitMQClient } from '../../../message-broker';
import { IAuhtService } from '../service/auth.service';
import { FacebookUserType, GithubUserType, GoogleUserType, ILoginOptionsDto, IPasswordLoginDto, IWebAuthnLoginOptions, IWebAuthnLoginVerification, IWebAuthnRegisterOptions, TYPES } from '../@types';
import { randomUUID } from 'crypto';
import { AccessTokenMiddleware, Middlewares, RequestValidator, MergeTokensMiddllware, RefreshTokenMiddleware } from '../middleware';

import { config } from '../../../config';
import { passportGoogle } from '../oauth2/google';
import { passportGithub } from '../oauth2/github';
import { passportFacebook } from '../oauth2/facebook';
import { encrypt, extractValue } from '../../../utils';
export interface RegisterDto {
  userId: string;
  email: string;
  userName: string;
  fullName: string;
  password: string;
  createdAt: string;
  updatedAt: string;
}

const FE_URL = process.env.NODE_ENV === "production" ? "https://www." + config["ORIGIN"] : config["ORIGIN"]
const FB_AVATAR = "https://d3lugnp3e3fusw.cloudfront.net/143086968_2856368904622192_1959732218791162458_n.png"

@controller('/api/v1/auth')
export class AuthController {
  constructor(@inject(TYPES.AuthService) private readonly _service: IAuhtService) { }
  @httpPatch("/validate-otp")
  async Validate2FA(@requestBody() body: { email: string, token: string }) {
    const { email, token } = body
    await this._service.Validate2FA(email, token)
  }
  @httpDelete("/mf-otps")
  async Delete2FA(@queryParam("email") email: string) {
    await this._service.Delete2FA(email)
  }
  @httpGet("/mf-otps")
  async GetMFOTPS(@queryParam("email") email: string, @response() res: Response) {
    return res.json(await this._service.Find2Fa(email))
  }
  @httpPost("/verify-otp")
  async VerifyOTP(@requestBody() body: { email: string, token: string }) {
    const { email, token } = body
    await this._service.Enable2FA(email, token)
  }
  @httpGet("/generate-mfa")
  async GenerateMFA(
    @queryParam("email") email: string, @response() res: Response
  ) {
    const url = await this._service.Create2FA(email)
    return res.send(`<img src="${url}"  width="200" alt="" srcSet="" />
    `)
  }
  @httpPost('/register', ...Middlewares.postRegisterCheck)
  async Register(@request() req: Request, @requestBody() dto: RegisterDto, @response() res: Response) {
    const id = randomUUID();
    dto.userId = id
    const result = await this._service.Registration(dto)
    // return res.cookie('token', result['refreshToken']).json({
    //   ok: 'ok',
    //   id: result['res']['userId'],
    //   email: result['res']['email'],
    //   full_name: result['res']['fullName'],
    //   user_name: result['res']['userName'],
    //   access_token: result['accessToken'],
    // });
    this.CookieReturn(res, { ...result })
    res.json(id)
  }
  @httpPost('/login-options')
  async LoginOptions(@requestBody() dto: ILoginOptionsDto, @response() res: Response) {
    const mf = await this._service.Find2Fa(dto.email)
    const otps = await this._service.LoginOptions(dto.email)
    return res.json({ ...otps, ...mf });
  }

  CookieReturn(res: Response, tokens: { access: string[], refresh: string[] }) {
    const { access, refresh } = tokens
    res
      .cookie("accessH", access[0], {
        sameSite: "strict",
        secure: process.env.NODE_ENV === "production",
        domain: config["COOKIES_DOMAIN"],
        maxAge: 2 * 60 * 60 * 1000
      })
      .cookie("accessS", access[1], {
        sameSite: "strict",
        secure: process.env.NODE_ENV === "production",
        httpOnly: true,
        domain: config["COOKIES_DOMAIN"],
        maxAge: 2 * 60 * 60 * 1000
      })
      .cookie("refreshH", refresh[0], {
        sameSite: "strict",
        secure: process.env.NODE_ENV === "production",
        domain: config["COOKIES_DOMAIN"],
        maxAge: 4 * 60 * 60 * 1000
      })
      .cookie("refreshS", refresh[1],
        {
          sameSite: "strict",
          secure: process.env.NODE_ENV === "production",
          httpOnly: true,
          domain: config["COOKIES_DOMAIN"],
          maxAge: 2 * 60 * 60 * 1000
        })
  }
  @httpPost('/login-password')
  async LoginPassword(@requestBody() dto: IPasswordLoginDto, @request() req: Request, @response() res: Response) {
    const result = await this._service.PasswordLogin(dto);
    this.CookieReturn(res, result)
  }
  @httpGet("/login-test", MergeTokensMiddllware, AccessTokenMiddleware, RefreshTokenMiddleware)
  async LoginTest(@response() res: Response) {
    return res.json({ "abc": "abc" })
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
    const result = await this._service.WebAuthnLoginVerification(dto.email, dto.data);
    return res.cookie('rft', result['refreshToken'], { sameSite: "strict", httpOnly: true, secure: process.env.NODE_ENV === "production", domain: config["COOKIES_DOMAIN"], maxAge: 2 * 60 * 60 * 1000 }).json({
      id: result['res']['userId'],
      email: result['res']['email'],
      full_name: result['res']['fullName'],
      user_name: result['res']['userName'],
      access_token: result['accessToken'],
    });
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
    session: false
  }))
  @httpGet("/oauth2", passportGoogle.authenticate("google", {
    failureRedirect: FE_URL + "/signin",
    session: false,
  }))
  async TestPCB(@request() req: Request, @response() res: Response) {
    // console.log(req["_passport"]["instance"]["_strategies"]["google"])
    const user = req.user as GoogleUserType

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
    res.redirect(FE_URL + "/setup")
  }

  @httpGet("/oauth-request-github", passportGithub.authenticate("github", { scope: ['user:email'], session: false }))
  async OauthGithub() { }
  @httpGet("/oauth2-github", passportGithub.authenticate("github", {
    session: false
  }))
  async OauthGithubCb(@request() req: Request, @response() res: Response) {
    const user = req.user as GithubUserType
    await this._service.HandleCredential(user)
    const ssid = encrypt(user.id)


    res.cookie("_s", ssid, { sameSite: "strict", httpOnly: true, secure: process.env.NODE_ENV === "production", domain: config["COOKIES_DOMAIN"], maxAge: 3 * 60 * 1000 })
    res.cookie("_avt", user.photos[0].value, { sameSite: "strict", httpOnly: true, secure: process.env.NODE_ENV === "production", domain: config["COOKIES_DOMAIN"], maxAge: 3 * 60 * 1000 })
    res.cookie("_p", "github", { sameSite: "strict", httpOnly: true, secure: process.env.NODE_ENV === "production", domain: config["COOKIES_DOMAIN"], maxAge: 3 * 60 * 1000 })
    // const uri = "name=" + encodeURIComponent(user.displayName) + "&email=" + encodeURIComponent(user.em)
    // console.log((uri));
    // res.cookie("alo", "Hello", { maxAge: 60 * 1000 })
    // res.redirect(config["ORIGIN"] + "/setup?" + uri)
    // console.log(user)
    // await this._service.HandleCredential(user)
    res.redirect(FE_URL + "/setup")
  }
  @httpGet("/oauth-request-facebook", passportFacebook.authenticate("facebook", { session: false }))
  async OauthFacebookb() { }
  @httpGet("/oauth2-facebook", passportFacebook.authenticate("facebook", { session: false }))
  async OauthFacebookCb(@request() req: Request, @response() res: Response) {
    const user = req.user as FacebookUserType
    await this._service.HandleCredential(user)
    const ssid = encrypt(user.id)

    res.cookie("_s", ssid, { sameSite: "strict", httpOnly: true, secure: process.env.NODE_ENV === "production", domain: config["COOKIES_DOMAIN"], maxAge: 3 * 60 * 1000 })

    res.cookie("_avt", FB_AVATAR, { sameSite: "strict", httpOnly: true, secure: process.env.NODE_ENV === "production", domain: config["COOKIES_DOMAIN"], maxAge: 3 * 60 * 1000 })
    res.cookie("_p", "facebook", { sameSite: "strict", httpOnly: true, secure: process.env.NODE_ENV === "production", domain: config["COOKIES_DOMAIN"], maxAge: 3 * 60 * 1000 })
    // const uri = "name=" + encodeURIComponent(user.displayName) + "&email=" + encodeURIComponent(user.em)
    // console.log((uri));
    // res.cookie("alo", "Hello", { maxAge: 60 * 1000 })
    // res.redirect(config["ORIGIN"] + "/setup?" + uri)
    res.redirect(FE_URL + "/setup")
  }

  @httpGet("/login/success")
  async LoginSuccess(@request() req: Request, @response() resp: Response) {
    if (req.headers.cookie) {
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
      const res = await this._service.HandleSetupCredential(sValue, pValue, eValue)
      resp.clearCookie("_p").clearCookie("_e").clearCookie("_s").clearCookie("_avt")
      return resp.cookie('rft', res['refreshToken'], { sameSite: "strict", httpOnly: true, secure: process.env.NODE_ENV === "production", domain: config["COOKIES_DOMAIN"], maxAge: 2 * 60 * 60 * 1000 }).json({
        isLoginBefore: res.isLoginBefore,
        id: res['id'],
        picture: avtValue,
        email: res['email'],
        full_name: res['fullName'],
        user_name: res['userName'],
        access_token: res['accessToken'],
        provider: pValue
      });
    } else {

    }
  }
  @httpPost("/logout")
  async Logout(@response() res: Response) {
    res.clearCookie("rft");
  }
  @httpPost("/update-status")
  async UpdateStatusCode(@request() req: Request, @requestBody() body: { provider: string, id: string }, @response() res: Response) {
    const { provider, id } = body
    console.log(body);

    await this._service.UpdateStatusLogin(id, provider)
  }
  @httpGet("/passkeys")
  async getAllPasskeys(@queryParam("email") email: string, @response() res: Response) {
    console.log(email);
    const passkeys = await this._service.FindPasskeys(email)

    return res.json(passkeys)
  }
  @httpDelete("/passkey")
  async DeletePasskey(@queryParam("i") i: string, @queryParam("u") u: string, @response() res: Response) {
    await this._service.DeletePasskeys(i, u)
  }
  @httpPatch("/newpassword")
  async UpdatePassword(@requestBody() body: { email: string, oldPassword: string, newPassword: string }) {
    const { email, oldPassword, newPassword } = body
    await this._service.ChangePassword(email, oldPassword, newPassword)
  }
}
