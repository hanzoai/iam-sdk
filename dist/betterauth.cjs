'use strict';

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

exports.hanzoIamProvider = iamProvider;
exports.hanzoIamSocialProvider = iamProvider;
exports.iamProvider = iamProvider;
//# sourceMappingURL=betterauth.cjs.map
//# sourceMappingURL=betterauth.cjs.map