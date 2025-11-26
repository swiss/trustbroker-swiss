# Hardened SAML XSD schemas

- limit assertions to 1 to avoid attacks with multiple-assertion (aiming for accidental use of unvalidated assertions)
- drop Extensions (could be used to include any XML, e.g. second assersion or second Response - not really an issue issue if we
  use DOM navigation and ignore the extensions)
- URL namespace references kept (no issue when resolution of external entity references is disabled during XML parsing)
