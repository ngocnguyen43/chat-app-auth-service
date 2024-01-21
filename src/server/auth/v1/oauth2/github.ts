import { Strategy as GithubStartegy } from "passport-github2"
import passport from "passport"
import { config } from "../../../config"

export const passportGithub = passport.use(new GithubStartegy({
    clientID: config["GITHUB_CLIENT_ID"],
    clientSecret: config["GITHUB_CLIENT_SECRET"],
    callbackURL: config["ORIGIN_API"] + "/auth/oauth2-github",

}, (req, actk, rftk, profile, cb) => {
    cb(null, profile)
}))

// passportGithub.serializeUser((user, cb) => {
//     // console.log(user)
//     process.nextTick(
//         () =>
//             cb(null, user)
//     )
// })
// passportGithub.deserializeUser(((id, cb) => {
//     process.nextTick(() =>
//         cb(null, id)
//     )
// }))