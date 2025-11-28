# Common Stuff

XTB in its core works with:

- SAML
- Apache commons

In addition to these, our own classes are the main transitive APIs we expose.

Rules to put classes into common:

- No active spring beans. Use @Bean factories in @Configuration classes where you need them.
- Any library you at as implementation should not cause side effects on modules depending on common.
