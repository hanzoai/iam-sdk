// src/betterauth.ts
function iamProvider(config) {
  const baseUrl = config.serverUrl.replace(/\/+$/, "");
  return {
    id: "iam",
    name: "IAM",
    type: "oidc",
    issuer: baseUrl,
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    authorization: {
      url: `${baseUrl}/oauth/authorize`,
      params: { scope: "openid profile email" }
    },
    token: { url: `${baseUrl}/oauth/token` },
    userinfo: { url: `${baseUrl}/oauth/userinfo` },
    profile(profile) {
      return {
        id: profile.sub ?? profile.id ?? "",
        name: profile.displayName ?? profile.name ?? profile.preferred_username ?? "",
        email: profile.email ?? "",
        image: profile.avatar ?? profile.picture ?? null
      };
    }
  };
}

export { iamProvider as hanzoIamProvider, iamProvider as hanzoIamSocialProvider, iamProvider };
//# sourceMappingURL=betterauth.js.map
//# sourceMappingURL=betterauth.js.map