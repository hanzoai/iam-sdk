'use strict';

var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});

// src/passport.ts
function createIamPassportStrategy(config) {
  const { Strategy: OAuth2Strategy } = __require("passport-oauth2");
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
  return new OAuth2Strategy(
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