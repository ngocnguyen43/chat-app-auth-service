import { Strategy as FacebookStartegy } from "passport-facebook"
import passport from "passport"
import { config } from "../../../config"

export const passportFacebook = passport.use(new FacebookStartegy({
    clientID: config["FACEBOOK_APP_ID"],
    clientSecret: config["FACEBOOK_APP_SECRET"],
    callbackURL: config["ORIGIN_API"] + "/auth/oauth2-facebook",
    state: true
}, (actk, rftk, profile, cb) => {
    cb(null, profile)
}))

passportFacebook.serializeUser((user, cb) => {
    // console.log(user)
    process.nextTick(
        () =>
            cb(null, user)
    )
})
passportFacebook.deserializeUser(((id, cb) => {
    process.nextTick(() =>
        cb(null, id)
    )
}))