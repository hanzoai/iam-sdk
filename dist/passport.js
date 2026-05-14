import OAuth2Strategy from 'passport-oauth2';

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

export { createIamPassportStrategy };
//# sourceMappingURL=passport.js.map
//# sourceMappingURL=passport.js.map