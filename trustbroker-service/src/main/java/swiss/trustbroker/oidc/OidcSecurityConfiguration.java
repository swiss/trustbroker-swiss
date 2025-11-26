/*
 * Copyright (C) 2024 trustbroker.swiss team BIT
 *
 * This program is free software.
 * You can redistribute it and/or modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See the GNU Affero General Public License for more details.
 * You should have received a copy of the GNU Affero General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 */

package swiss.trustbroker.oidc;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.micrometer.common.util.StringUtils;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.velocity.app.VelocityEngine;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import swiss.trustbroker.audit.service.AuditService;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.mapping.service.ClaimsMapperService;
import swiss.trustbroker.mapping.service.QoaMappingService;
import swiss.trustbroker.metrics.service.MetricsService;
import swiss.trustbroker.oidc.opensaml5.OpenSaml5AuthenticationProvider;
import swiss.trustbroker.oidc.opensaml5.OpenSaml5AuthenticationRequestResolver;
import swiss.trustbroker.oidc.opensaml5.OpenSaml5AuthenticationTokenConverter;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.sessioncache.service.JwkCacheService;
import swiss.trustbroker.sso.service.SsoService;
import swiss.trustbroker.util.ApiSupport;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
@Slf4j
public class OidcSecurityConfiguration {

	private final ClientConfigInMemoryRepository registeredClientRepository;

	private final CustomRelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

	private final TrustBrokerProperties properties;

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final QoaMappingService qoaMappingService;

	private final JwkCacheService jwkCacheService;

	private final ServerProperties serverProperties;

	private final ApiSupport apiSupport;

	private final ScriptService scriptService;

	private final ClaimsMapperService claimsMapperService;

	private final AuditService auditService;

	private final SsoService ssoService;

	private final VelocityEngine velocityEngine;

	private final QoaMappingService qoaService;

	private final CustomOAuth2AuthorizationService customOAuth2AuthorizationService;

	public final MetricsService metricsService;

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		// use top-level package to control sub-system debug flag
		return web -> web.debug(LoggerFactory.getLogger("spring.security.debug")
											 .isDebugEnabled());
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		// CORS support with Access-Control-Allow-Origin=* unusable for OIDC, we override in CorsSupport on the wire
		// check WebConfiguration for setup and org.springframework.web.cors.DefaultCorsProcessor for behavior
		http.cors(AbstractHttpConfigurer::disable);

		// CSRF is disabled because of issues with our SPA and SAM/OIDC handling
		http.csrf(AbstractHttpConfigurer::disable);

		// Handled by HeaderBuilder - it may use frame-ancestors instead, so Spring must not set Frame Options
		http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable));

		// access control (also see AccessFilter when running along trustbroker-application)
		http.authorizeHttpRequests(authorizeRequests ->
				// require authentication for all requests used for OIDC handling
				authorizeRequests.requestMatchers(
										 antMatcher(ApiSupport.SPRING_OAUTH2 + "/**"),
										 antMatcher(ApiSupport.SPRING_SAML_LOGIN_CTXPATH + "/**"),
										 antMatcher(ApiSupport.KEYCLOAK_REALMS + "/**")
								 )
								 .authenticated()
								 .anyRequest()// anything else allowed (default anyway but be explicit)
								 .permitAll()
		);

		// authentication setup
		http.saml2Login(saml2 -> saml2
				.failureHandler(new CustomFailureHandler("saml2", relyingPartyDefinitions, properties))
				.authenticationConverter(new OpenSaml5AuthenticationTokenConverter(relyingPartyRegistrationRepository))
				.authenticationManager(new ProviderManager(customAuthenticationProvider())).
									  loginPage(apiSupport.getErrorPageUrl()));

		// logout disabled on IdP side as we act as a federation service
		http.saml2Logout(AbstractHttpConfigurer::disable);

		// logout is not connected to token revocation by default as OAuth 2.1 is focused on authorization, not authentication.
		// https://docs.spring.io/spring-security/reference/servlet/authentication/logout.html#customizing-logout-uris
		http.logout(logout -> logout
			.logoutSuccessHandler(logoutSuccessHandler())
			.logoutUrl(logoutPath()) // LogoutFilter currently ignores this and always uses /logout
			.clearAuthentication(true)
			.invalidateHttpSession(true)
			.deleteCookies(serverProperties.getServlet()
										   .getSession()
										   .getCookie()
										   .getName()));

		// for K8S resilience and multi web-session support we need a special tomcat session manager
		http.sessionManagement(sessionManage -> sessionManage
				.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
				.maximumSessions(-1)); // unlimited

		// all done
		return http.build();
	}

	private String logoutPath() {
		var logoutUri = WebUtil.getValidatedUri(properties.getOidc().getEndSessionEndpoint());
		if (logoutUri == null || StringUtils.isEmpty(logoutUri.getPath())) {
			log.error("trustbroker.config.oidc.endSessionEndpoint=\"{}\" is not a valid URI, using default /logout",
					properties.getOidc().getEndSessionEndpoint());
			return "/logout";
		}
		return logoutUri.getPath();
	}

	/**
	 * Config secret decoding support.
	 * @return returns a
	 * https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/crypto/password
	 * /DelegatingPasswordEncoder.html
	 * so you can use any of the variants provided by
	 * https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/crypto/factory
	 * /PasswordEncoderFactories.html
	 */
	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Bean
	public LogoutSuccessHandler logoutSuccessHandler() {
		return new CustomLogoutSuccessHandler(registeredClientRepository, properties, relyingPartyDefinitions,
				customOAuth2AuthorizationService, ssoService, velocityEngine);
	}

	/**
	 * Token signer support based on rotating keys periodically using the oldest valid one first.
	 * Keys are retrieved on the /oauth2/jwks or the /realms/id/protocols/openid-connect/certs endpoint.
	 * @return
	 */
	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		return new RotateJwkSource<>(jwkCacheService, metricsService);
	}

	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	/**
	 * Tokens are customized with some additional OIDC claims and the business claims configured.
	 * The token and access_token are mostly the same.
	 * @param jwkSource
	 * @return
	 */
	@Bean
	OAuth2TokenGenerator<OAuth2Token> tokenGenerator(JWKSource<SecurityContext> jwkSource, OidcEncryptionKeystoreService oidcEncryptionKeystoreService) {
		JwtEncoder jwtEncoder = new CustomJwtEncoder(properties, relyingPartyDefinitions, jwkSource, oidcEncryptionKeystoreService);
		var jwtGenerator = new JwtGenerator(jwtEncoder);
		jwtGenerator.setJwtCustomizer(tokenCustomizer(jwkSource));
		var accessTokenGenerator = new OAuth2AccessTokenGenerator();
		var refreshTokenGenerator = new CustomRefreshTokenGenerator(jwtEncoder, jwkSource, new OAuth2RefreshTokenGenerator(), properties, relyingPartyDefinitions);
		return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
	}

	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(JWKSource<SecurityContext> jwkSource) {
		// Customize OAuth2Token payload
		return new JwtTokenCustomizer(properties, relyingPartyDefinitions, scriptService, claimsMapperService, auditService,
				qoaService, jwkSource);
	}

	/**
	 * The SAML authentication principal is the main data we use to attach all login state.
	 * We therefore need to override some spring-security defaults and extend the handling to map
	 * OIDC prompt=login to SAML AuthnRequest.forceAuth=TRUE.
	 * @return
	 */
	@Bean
	Saml2AuthenticationRequestResolver authenticationRequestResolver() {
		var authenticationRequestResolver = new OpenSaml5AuthenticationRequestResolver(relyingPartyResolver());
		var authnRequestCustomizer = new OidcAuthnRequestContextCustomizer(properties, relyingPartyDefinitions, qoaMappingService);
		authenticationRequestResolver.setAuthnRequestCustomizer(authnRequestCustomizer);
		return authenticationRequestResolver;
	}

	private RelyingPartyRegistrationResolver relyingPartyResolver() {
		return new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);
	}

	private OpenSaml5AuthenticationProvider customAuthenticationProvider() {
		var authenticationProvider = new OpenSaml5AuthenticationProvider();
		authenticationProvider.setResponseValidator(customResponseValidator());
		return authenticationProvider;
	}

	private Converter<OpenSaml5AuthenticationProvider.ResponseToken,
			Saml2ResponseValidatorResult> customResponseValidator() {
		var delegate = OpenSaml5AuthenticationProvider.createDefaultResponseValidator();
		return new OidcResponseValidator(properties, delegate);
	}

}
