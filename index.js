import express from 'express'
import dotenv from 'dotenv'
import session from 'express-session'
import passport from 'passport'
import { Strategy as OIDCStrategy } from "passport-openidconnect"

function pick(obj, properties) {
    return Object.fromEntries(Object.entries(obj).filter(([key]) => properties.includes(key)))
}

dotenv.config()

const app = express()
app.set('view engine', 'ejs')
app.use(express.static('public'))

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
}))

app.use(passport.initialize())
app.use(passport.session())

// -------------------------------------------------------------------------
// 3. Passport serialisation helpers ---------------------------------------
// Instead of storing the full profile in the cookie, we keep just the id &
// provider. You can expand this with a DB lookup if you have a user model.
passport.serializeUser((user, done) => {
    const a = user._json
    done(null, user);
});

passport.deserializeUser((obj, done) => {
    done(null, obj); // In a real app perform DB lookup here
});



const providers = JSON.parse(process.env.OIDC_PROVIDERS).map(p => ({
    name: p.name,
    issuer: p.serverUrl,
    authorizationURL: `${p.serverUrl}/oidc/auth`,
    tokenURL: `${p.serverUrl}/oidc/token`,
    userInfoURL: `${p.serverUrl}/oidc/me`,
    clientID: `${p.clientId}`,
    clientSecret: `${p.clientSecret}`,
    callbackURL: `http://localhost:3000/auth/${p.name}/callback`,
}))

providers.forEach(({ name, ...cfg }) => {
    passport.use(
        name,
        new OIDCStrategy({
            ...cfg,
            scope: 'openid profile',
            passReqToCallback: false,
        },
            // (issuer, profile, cb) => {
            // NOTE: Important to have all args. Otherwise _json is not available
            (issuer, uiProfile, idProfile, context, idToken, accessToken, refreshToken, params, cb) => {
                const tst = uiProfile._json
                /*
                 * This verify callback is invoked after the provider has authenticated
                 * the user and returned profile information.
                 *
                 * In a real‑world app you would typically:
                 *   1. Look up or create the user record in your DB.
                 *   2. Attach application‑specific data.
                 *   3. Call `done(err, user)`.
                 *
                 * Here we simply add the provider name to the profile and return it.
                 */

                const user = { id: uiProfile.id, ...pick(uiProfile._json, ['id', 'name', 'isSupport']), provider: name }
                return cb(null, user);
            }),
    )
})

// 5. Convenience middleware ------------------------------------------------
function ensureAuth(req, res, next) {
    // Protect routes – redirect unauthenticated users to home
    if (req.isAuthenticated()) return next();
    res.redirect("/");
}

// -------------------------------------------------------------------------
// 6. Routes ---------------------------------------------------------------
app.get("/", (_req, res) => {
    res.json({ user: _req.user || null })
    // res.render("index", { user: _req.user, providers });
});

// Trigger login. Example: GET /auth/okta ➜ redirect to Okta login page.
app.get("/auth/:provider", (req, res, next) => {
    const { provider } = req.params;
    if (!providers.find(p => p.name === provider)) return res.status(404).send("Unknown provider");
    passport.authenticate(provider)(req, res, next);
});

// Callback URL hit by the provider after user authenticates.
app.get("/auth/:provider/callback", (req, res, next) => {
    const { provider } = req.params;
    if (!providers.find(p => p.name === provider)) return res.status(404).send("Unknown provider");
    passport.authenticate(provider, {
        failureRedirect: "/",
        successRedirect: "/"
    })(req, res, next);
});

// Logout destroys the session and Passport user.
app.get("/logout", (req, res) => {
    req.logout(() => {
        res.redirect("/");
    });
});

// -------------------------------------------------------------------------
// 7. Start server ----------------------------------------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
