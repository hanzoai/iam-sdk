'use strict';

var min = require('libphonenumber-js/min');

// src/validation.ts
var isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
var isValidPhone = (nationalDigits, countryCode) => {
  if (!nationalDigits || !countryCode) return false;
  const cc = countryCode.startsWith("+") ? countryCode : `+${countryCode}`;
  return min.isValidPhoneNumber(`${cc}${nationalDigits}`);
};

exports.isValidEmail = isValidEmail;
exports.isValidPhone = isValidPhone;
//# sourceMappingURL=validation.cjs.map
//# sourceMappingURL=validation.cjs.map