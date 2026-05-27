import { isValidPhoneNumber } from 'libphonenumber-js/min';

// src/validation.ts
var isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
var isValidPhone = (nationalDigits, countryCode) => {
  if (!nationalDigits || !countryCode) return false;
  const cc = countryCode.startsWith("+") ? countryCode : `+${countryCode}`;
  return isValidPhoneNumber(`${cc}${nationalDigits}`);
};

export { isValidEmail, isValidPhone };
//# sourceMappingURL=validation.js.map
//# sourceMappingURL=validation.js.map