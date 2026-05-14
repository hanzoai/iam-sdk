'use strict';

var OAuth2Strategy = require('passport-oauth2');

function _interopDefault (e) { return e && e.__esModule ? e : { default: e }; }

var OAuth2Strategy__default = /*#__PURE__*/_interopDefault(OAuth2Strategy);

// src/passport.ts
function createIamPassportStrategy(config) {
  const baseUrl = config.serverUrl.replace(/\/+$/, "");
  const verify = async (...args) => {
    const accessToken = args[1];
    const refreshToken = args[2];
    const done = args[4];
    try {
      const res = await fetch(`${baseUrl}/oauth/userinfo`, {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      if (!res.ok) {
        return done(new Error(`IAM userinfo failed: ${res.status}`));
      }
      const userinfo = await res.json();
      done(null, { accessToken, refreshToken, userinfo });
    } catch (err) {
      done(err instanceof Error ? err : new Error(String(err)));
    }
  };
  return new OAuth2Strategy__default.default(
    {
      authorizationURL: `${baseUrl}/oauth/authorize`,
      tokenURL: `${baseUrl}/oauth/token`,
      clientID: config.clientId,
      clientSecret: config.clientSecret ?? "",
      callbackURL: config.callbackUrl,
      scope: config.scope ?? "openid profile email",
      state: true,
      pkce: true,
      passReqToCallback: true
    },
    verify
  );
}

exports.createIamPassportStrategy = createIamPassportStrategy;
//# sourceMappingURL=passport.cjs.map
//# sourceMappingURL=passport.cjs.map