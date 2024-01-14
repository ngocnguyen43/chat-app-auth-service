import { Strategy as GoogleStartegy } from "passport-google-oauth20"
import passport from "passport"
import { config } from "../../../config"

export const passportGoogle = passport.use(new GoogleStartegy({
    clientID: config["GOOGLE_CLIENT_ID"],
    clientSecret: config["GOOGLE_CLIENT_SECRET"],
    callbackURL: "http://localhost:80/api/v1/auth/oauth2",
    passReqToCallback: true,

    state: true
}, async (req, accessToken, refreshToken, profile, cb) => {
    // console.log("checkk:::", profile);
    req.user = profile._json
    cb(null, profile._json)
}))

passportGoogle.serializeUser((user, cb) => {
    // console.log(user)
    process.nextTick(
        () =>
            cb(null, user)
    )
})
passportGoogle.deserializeUser(((id, cb) => {
    process.nextTick(() =>
        cb(null, id)
    )
}))