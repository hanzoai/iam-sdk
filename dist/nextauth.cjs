'use strict';

// src/nextauth.ts
function IamProvider(options) {
  const issuer = options.serverUrl.replace(/\/$/, "");
  const checks = options.checks ?? ["state"];
  return {
    id: "iam",
    name: "IAM",
    type: "oauth",
    wellKnown: `${issuer}/.well-known/openid-configuration`,
    idToken: true,
    checks,
    authorization: { params: { scope: "openid profile email" } },
    profile(profile) {
      return {
        id: profile.sub,
        name: profile.displayName || profile.name || profile.preferred_username || profile.email || "",
        email: profile.email,
        image: profile.avatar || profile.picture || null
      };
    },
    style: {
      bg: "#050508",
      text: "#fff",
      logo: ""
    },
    options
  };
}

exports.HanzoIamProvider = IamProvider;
exports.IamProvider = IamProvider;
//# sourceMappingURL=nextauth.cjs.map
//# sourceMappingURL=nextauth.cjs.map