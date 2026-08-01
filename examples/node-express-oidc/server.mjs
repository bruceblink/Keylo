import express from "express";
import session from "express-session";
import * as oidc from "openid-client";

const port = Number(process.env.PORT ?? 3000);
const issuer = requiredEnv("KEYLO_ISSUER");
const clientId = requiredEnv("OIDC_CLIENT_ID");
const redirectUri = process.env.OIDC_REDIRECT_URI ?? `http://127.0.0.1:${port}/oidc/callback`;
const clientSecret = process.env.OIDC_CLIENT_SECRET;
const sessionSecret = requiredEnv("SESSION_SECRET");

const app = express();
app.set("trust proxy", 1);
app.use(
  session({
    name: "keylo_rp_session",
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: new URL(redirectUri).protocol === "https:",
    },
  }),
);

const configuration = await oidc.discovery(new URL(issuer), clientId, clientSecret);

/**
 * Read a required configuration value early so a broken deployment cannot start
 * with an accidental default identity boundary.
 */
function requiredEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} must be configured`);
  }
  return value;
}

/**
 * Construct this application's externally visible callback URL. Behind a proxy,
 * use the configured redirect URI instead of browser-controlled request headers.
 */
function callbackUrl(request) {
  return new URL(request.originalUrl, redirectUri).toString();
}

/**
 * Remove one-time login material after every callback outcome. This prevents a
 * browser back button or replayed callback from exchanging the same code twice.
 */
function clearLoginTransaction(request) {
  delete request.session.oidc;
}

/**
 * Bind the authorization response to the issuer discovered at startup. Keylo
 * includes `iss` in every callback, so a missing or substituted value is fatal.
 */
function hasExpectedIssuer(request) {
  return typeof request.query.iss === "string" && request.query.iss === issuer;
}

/**
 * Require the minimal validated user profile stored by the callback handler.
 * It never treats an unverified browser value as an authenticated identity.
 */
function requireUser(request, response, next) {
  if (!request.session.user) {
    return response.redirect("/login");
  }
  return next();
}

app.get("/login", async (request, response, next) => {
  try {
    const state = oidc.randomState();
    const nonce = oidc.randomNonce();
    const codeVerifier = oidc.randomPKCECodeVerifier();
    const codeChallenge = await oidc.calculatePKCECodeChallenge(codeVerifier);

    request.session.oidc = { state, nonce, codeVerifier };
    request.session.save((error) => {
      if (error) {
        next(error);
        return;
      }

      const authorizationUrl = oidc.buildAuthorizationUrl(configuration, {
        redirect_uri: redirectUri,
        response_type: "code",
        scope: "openid profile email",
        state,
        nonce,
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
      });
      response.redirect(authorizationUrl.href);
    });
  } catch (error) {
    next(error);
  }
});

app.get("/oidc/callback", async (request, response, next) => {
  const transaction = request.session.oidc;
  clearLoginTransaction(request);

  if (!transaction) {
    return response.status(400).send("OIDC login transaction is missing or expired.");
  }

  if (!hasExpectedIssuer(request)) {
    return response.status(400).send("OIDC callback issuer is missing or invalid.");
  }

  try {
    const tokens = await oidc.authorizationCodeGrant(
      configuration,
      new URL(callbackUrl(request)),
      {
        expectedState: transaction.state,
        expectedNonce: transaction.nonce,
        pkceCodeVerifier: transaction.codeVerifier,
        idTokenExpected: true,
      },
    );
    const claims = tokens.claims();

    request.session.user = {
      sub: claims.sub,
      name: claims.name,
      email: claims.email,
      emailVerified: claims.email_verified,
    };
    return request.session.save((error) => {
      if (error) {
        next(error);
        return;
      }
      response.redirect("/");
    });
  } catch (error) {
    return next(error);
  }
});

app.get("/", requireUser, (request, response) => {
  response.type("html").send(`<!doctype html><title>Keylo OIDC example</title><h1>Signed in</h1><pre>${escapeHtml(JSON.stringify(request.session.user, null, 2))}</pre><a href="/logout">Sign out</a>`);
});

app.get("/logout", (request, response, next) => {
  request.session.destroy((error) => {
    if (error) {
      next(error);
      return;
    }
    response.clearCookie("keylo_rp_session");
    response.redirect("/");
  });
});

/** Escape profile text before embedding it in the tiny demonstration HTML page. */
function escapeHtml(value) {
  return value.replace(/[&<>'"]/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "'": "&#39;",
    '"': "&quot;",
  })[character]);
}

app.use((error, _request, response, _next) => {
  console.error("OIDC request failed", error);
  response.status(500).send("OIDC login failed.");
});

app.listen(port, "127.0.0.1", () => {
  console.log(`Open http://127.0.0.1:${port}`);
});
