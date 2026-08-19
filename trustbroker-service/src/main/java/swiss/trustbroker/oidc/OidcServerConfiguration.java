/*
 * Copyright (C) 2026 trustbroker.swiss team BIT
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

import java.time.Clock;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.JwtClientAssertionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.exception.GlobalExceptionHandler;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.mapping.service.QoaMappingService;
import swiss.trustbroker.metrics.service.MetricsService;
import swiss.trustbroker.oidc.cache.service.OidcMetadataCacheService;
import swiss.trustbroker.oidc.jackson.ObjectMapperFactory;
import swiss.trustbroker.oidc.pkce.PublicClientRefreshTokenAndTokenExchangeAuthenticationConverter;
import swiss.trustbroker.oidc.pkce.PublicClientRefreshTokenAuthenticationProvider;
import swiss.trustbroker.saml.service.RelyingPartyService;
import swiss.trustbroker.script.service.ScriptService;
import tools.jackson.databind.ObjectMapper;

@Configuration
@AllArgsConstructor
@Slf4j
public class OidcServerConfiguration {

	private static final String ID_TOKEN_ENCRYPTION_ALG = "id_token_encryption_alg_values_supported";

	private static final String ID_TOKEN_ENCRYPTION_METHOD = "id_token_encryption_enc_values_supported";

	private static final String USERINFO_ENCRYPTION_ALG = "userinfo_encryption_alg_values_supported";

	private static final String USERINFO_ENCRYPTION_METHOD = "userinfo_encryption_enc_values_supported";

	private final OidcProperties oidcProperties;

	private final ClientConfigInMemoryRepository registeredClientRepository;

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final TrustBrokerProperties trustBrokerProperties;

	private final ScriptService scriptService;

	private final ObjectMapper objectMapper;

	private final OidcEncryptionKeystoreService encryptionKeystoreService;

	private final OidcMetadataCacheService oidcMetadataCacheService;

	private final RelyingPartyService relyingPartyService;

	private final RelyingPartySetupService relyingPartySetupService;

	private final QoaMappingService qoaMappingService;

	private final OidcAuditService auditService;

	// no in-memory session tracking
	// note: this bean needs to be in the bean registry, see OAuth2AuthorizationServerConfigurer
	// using OAuth2ConfigurerUtils.getOptionalBean, setting it in HttpSecurity has no effect:
	// httpSecurity.setSharedObject(SessionRegistry.class, sessionRegistry)
	@Bean
	public SessionRegistry sessionRegistry() {
		return new CustomSessionRegistry();
	}

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(
			HttpSecurity http, OAuth2AuthorizationService authorizationService, JwtDecoder jwtDecoder,
			JWKSource<SecurityContext> jwkSource, CustomOAuth2AuthorizationService customOAuth2AuthorizationService,
			OAuth2TokenGenerator<OAuth2Token> tokenGenerator) {

		// setup spring-authorization-server for login federation
		var authServerConfigurer = new OAuth2AuthorizationServerConfigurer();

		// mandatory client authentication functionality (client login required for /authorize, /token, /introspect, ...)
		authServerConfigurer.clientAuthentication(clientAuthentication -> clientAuthentication
				.authenticationConverters(converters ->
					converters.add(new PublicClientRefreshTokenAndTokenExchangeAuthenticationConverter()))
				// https://github.com/spring-projects/spring-authorization-server/pull/1432
				.authenticationProviders(providers ->
						providers.add(new PublicClientRefreshTokenAuthenticationProvider(registeredClientRepository)))
				.errorResponseHandler(new CustomFailureHandler(
						"authenticate", relyingPartyDefinitions, trustBrokerProperties))
		);

		// mandatory /authorize endpoint
		authServerConfigurer.authorizationEndpoint(authorizeEndpoint -> authorizeEndpoint
				.authenticationProviders(configureAuthorizationProviderChain())
				.errorResponseHandler(new CustomFailureHandler(
						"authorize", relyingPartyDefinitions, trustBrokerProperties)));

		// mandatory /token endpoint
		authServerConfigurer.tokenEndpoint(tokenEndpoint -> tokenEndpoint
				.authenticationProvider(new CustomOAuth2TokenExchangeAuthenticationProvider(registeredClientRepository,
						customOAuth2AuthorizationService, oidcMetadataCacheService, relyingPartyDefinitions, trustBrokerProperties,
						relyingPartyService, relyingPartySetupService, qoaMappingService, tokenGenerator))
				.authenticationProvider(jwtClientAssertionAuthenticationProvider(registeredClientRepository, authorizationService, jwtDecoder))
				.accessTokenRequestConverter(new CustomOAuth2TokenExchangeAuthenticationConverter())
				.errorResponseHandler(new CustomFailureHandler(
						"token", relyingPartyDefinitions, trustBrokerProperties)));

		// optional /introspect (investigate token) and /userinfo endpoints
		if (oidcProperties.isIntrospectionEnabled()) {
			authServerConfigurer.tokenIntrospectionEndpoint(introspectEndpoint -> introspectEndpoint
					.authenticationProvider(new CustomTokenIntrospectionAuthenticationProvider(
							registeredClientRepository, authorizationService, relyingPartyDefinitions, trustBrokerProperties))
					.errorResponseHandler(new CustomFailureHandler(
							"introspect", relyingPartyDefinitions, trustBrokerProperties)));
		}

		// optional /userinfo endpoint
		if (oidcProperties.isUserInfoEnabled()) {
			// OidcUserInfoAuthenticationProvider works with a OidcUserInfoAuthenticationToken converted from the session
			// The access_token is globally checked with the configuration below.
			authServerConfigurer.oidc(oidc -> oidc
					.userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
							.userInfoMapper(createUserInfoMapper())
							.authenticationProvider(new CustomUserInfoAuthenticationProvider(
									authorizationService, new JwtAuthenticationProvider(jwtDecoder), new OidcUserInfoAuthenticationProvider(authorizationService)))
							.userInfoResponseHandler(
									new CustomUserInfoResponseHandler(relyingPartyDefinitions, trustBrokerProperties, objectMapper, jwkSource, encryptionKeystoreService))
							.errorResponseHandler(new CustomFailureHandler(
									"userinfo", relyingPartyDefinitions, trustBrokerProperties))
					));
		}

		// optional /revoke endpoint (logout does not work here, must be done on spring-security /logout instead)
		if (oidcProperties.isRevocationEnabled()) {
			authServerConfigurer.tokenRevocationEndpoint(tokenRevocationEndpoint -> tokenRevocationEndpoint
					.revocationResponseHandler((request, response, authentication) ->
							response.setStatus(HttpStatus.OK.value()))
					.authenticationProvider(
							new CustomTokenRevocationAuthenticationProvider(authorizationService, trustBrokerProperties))
					.errorResponseHandler(new CustomFailureHandler(
							"revoke", relyingPartyDefinitions, trustBrokerProperties))
			);
		}

		// customize /logout handling coupling it with XTB multi-session handling during federated login
		authServerConfigurer.oidc(oidc -> oidc.providerConfigurationEndpoint(providerConfigurationEndpoint ->
				providerConfigurationEndpoint.providerConfigurationCustomizer(customizeProviderConfigurationEndpoint())
		));

		// setup spring-security handling on oidc protocol URLs
		// NOTE: If things go weird crosscheck with OidcSecurityConfiguration
		var endpointsMatcher = authServerConfigurer.getEndpointsMatcher();
		http.securityMatcher(endpointsMatcher)
			.authorizeHttpRequests(authorizeRequests -> authorizeRequests
					.requestMatchers(
							PathPatternRequestMatcher.pathPattern("/favicon.ico"),
							PathPatternRequestMatcher.pathPattern("/failure"))
					.permitAll() // skip these
					.anyRequest()
					.authenticated() // protect everything else
			)
			.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
			.with(authServerConfigurer, Customizer.withDefaults())
			.addFilterBefore(new LogTokenRequestsFilter(auditService, trustBrokerProperties), SecurityContextHolderFilter.class);

		// Redirect to the login page when not authenticated from the authorization endpoint
		http.exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(entryPoint(relyingPartyDefinitions)));

		return http.build();
	}

	private AuthenticationProvider jwtClientAssertionAuthenticationProvider(ClientConfigInMemoryRepository registeredClientRepository, OAuth2AuthorizationService authorizationService, JwtDecoder jwtDecoder) {
		var jwtClientAssertionAuthenticationProvider = new JwtClientAssertionAuthenticationProvider(registeredClientRepository, authorizationService);
		jwtClientAssertionAuthenticationProvider.setJwtDecoderFactory(new CustomJwtClientAssertionDecoderFactory(relyingPartyDefinitions, trustBrokerProperties, jwtDecoder));
		return jwtClientAssertionAuthenticationProvider;
	}

	private static Consumer<List<AuthenticationProvider>> configureAuthorizationProviderChain() {
		return authenticationProviders -> authenticationProviders.forEach(authenticationProvider -> {
			if (authenticationProvider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider oauth2Provider) {
				var authenticationValidator = new CustomRedirectUriValidator()
						.andThen(OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_SCOPE_VALIDATOR);
				oauth2Provider.setAuthenticationValidator(authenticationValidator);
			}
		});
	}

	@Bean
	BearerTokenResolver bearerTokenResolver() {
		DefaultBearerTokenResolver defaultBearerTokenResolver = new DefaultBearerTokenResolver();
		return new CustomBearerTokenResolver(defaultBearerTokenResolver, relyingPartyDefinitions, trustBrokerProperties);
	}

	Consumer<OidcProviderConfiguration.Builder> customizeProviderConfigurationEndpoint() {
		return providerConfiguration -> {
			providerConfiguration.claims(claimMap ->
					OidcConfigurationUtil.removeDisabledEndpointFromMetadataClaim(oidcProperties, claimMap)
			);

			// optional front-channel /logout support
			if (oidcProperties.isLogoutEnabled()) {
				OidcConfigurationUtil.setEndSessionEndpoint(oidcProperties, providerConfiguration);
			}
			if (oidcProperties.getSessionIFrameEndpoint() != null) {
				OidcConfigurationUtil.addClaimToProviderConfiguration(providerConfiguration, "check_session_iframe",
						oidcProperties.getSessionIFrameEndpoint());
			}
			// other optional configurations
			OidcConfigurationUtil.addClaimToProviderConfiguration(providerConfiguration,
					OAuth2AuthorizationServerMetadataClaimNames.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS,
					oidcProperties.isTlsClientCertificateBoundAccessTokens());
			OidcConfigurationUtil.addOptionalClaimToProviderConfiguration(providerConfiguration,
					OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED,
					oidcProperties.getGrantTypes());
			OidcConfigurationUtil.addOptionalClaimToProviderConfiguration(providerConfiguration,
					OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED,
					oidcProperties.getResponseTypes());
			OidcConfigurationUtil.addOptionalClaimToProviderConfiguration(providerConfiguration,
					OAuth2AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED,
					oidcProperties.getScopes());
			OidcConfigurationUtil.addOptionalClaimToProviderConfiguration(providerConfiguration,
					OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
					oidcProperties.getTokenEndpointAuthMethods());
			if (oidcProperties.isIntrospectionEnabled()) {
				OidcConfigurationUtil.addOptionalClaimToProviderConfiguration(providerConfiguration,
						OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED,
						oidcProperties.getIntrospectionEndpointAuthMethods());
			}
			if (oidcProperties.isRevocationEnabled()) {
				OidcConfigurationUtil.addOptionalClaimToProviderConfiguration(providerConfiguration,
						OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED,
						oidcProperties.getRevocationEndpointAuthMethods());
			}
			OidcConfigurationUtil.addOptionalClaimToProviderConfiguration(providerConfiguration,
					OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED,
					oidcProperties.getSubjectTypes());
			OidcConfigurationUtil.addOptionalClaimToProviderConfiguration(providerConfiguration,
					OAuth2AuthorizationServerMetadataClaimNames.CODE_CHALLENGE_METHODS_SUPPORTED,
					oidcProperties.getCodeChallengeMethods());
			OidcConfigurationUtil.addOptionalClaimToProviderConfiguration(providerConfiguration,
					OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED,
					oidcProperties.getIdTokenSigningAlgorithms());
			OidcConfigurationUtil.addOptionalClaimToProviderConfiguration(providerConfiguration,
					OAuth2AuthorizationServerMetadataClaimNames.DPOP_SIGNING_ALG_VALUES_SUPPORTED,
					oidcProperties.getDPoPSigningAlgValuesSupported());
			// encryption
			OidcConfigurationUtil.addOptionalClaimToProviderConfiguration(providerConfiguration,
					ID_TOKEN_ENCRYPTION_ALG, oidcProperties.getIdTokenEncryptionAlgorithms());
			OidcConfigurationUtil.addOptionalClaimToProviderConfiguration(providerConfiguration,
					ID_TOKEN_ENCRYPTION_METHOD, oidcProperties.getIdTokenEncryptionMethods());
			if (oidcProperties.isUserInfoEnabled()) {
				OidcConfigurationUtil.addOptionalClaimToProviderConfiguration(providerConfiguration,
						USERINFO_ENCRYPTION_ALG, oidcProperties.getUserInfoEncryptionAlgorithms());
				OidcConfigurationUtil.addOptionalClaimToProviderConfiguration(providerConfiguration,
						USERINFO_ENCRYPTION_METHOD, oidcProperties.getUserInfoEncryptionMethods());
			}
		};
	}

	private Function<OidcUserInfoAuthenticationContext, OidcUserInfo> createUserInfoMapper() {
		return context -> {
			var authentication = context.getAuthentication();
			Map<String, Object> claims = new HashMap<>();
			var principal = authentication.getPrincipal();
			var clientId = context.getAuthorization().getRegisteredClientId();
			var clientConfig = relyingPartyDefinitions.getOidcClientConfigById(clientId, trustBrokerProperties);
			if (clientConfig.isEmpty()) {
				throw new TechnicalException("Could not find client config for " + clientId);
			}
			Map<String, Object> tokenClaims = null;
			if (principal instanceof JwtAuthenticationToken jwtAuthenticationToken) {
				tokenClaims = jwtAuthenticationToken.getToken().getClaims();
			}
			if (principal instanceof BearerTokenAuthentication bearerTokenAuthentication) {
				tokenClaims = bearerTokenAuthentication.getTokenAttributes();
			}
			if (tokenClaims == null) {
				throw new TechnicalException("Missing token claims for client " + clientId);
			}
			claims = OidcUserInfoUtil.filterUnwantedClaims(tokenClaims, clientId,
					relyingPartyDefinitions, scriptService, trustBrokerProperties);
			return new OidcUserInfo(claims);
		};
	}

	@Bean
	public AuthenticationEntryPoint entryPoint(RelyingPartyDefinitions relyingPartyDefinitions) {
		return new CustomAuthenticationEntryPoint(relyingPartyDefinitions, trustBrokerProperties);
	}

	@Bean
	@ConditionalOnProperty(value = "trustbroker.config.serverMultiProcessed", havingValue = "true", matchIfMissing = true)
	public CustomOAuth2AuthorizationService authorizationService(
			JdbcTemplate jdbcTemplate,
			RegisteredClientRepository registeredClientRepository,
			TrustBrokerProperties trustBrokerProperties,
			GlobalExceptionHandler globalExceptionHandler,
			Clock clock,
			MetricsService metricsService) {
		var jsonMapper = ObjectMapperFactory.springSecObjectMapper();
		var authorizationService = new CustomOAuth2AuthorizationService(
				jdbcTemplate, registeredClientRepository, trustBrokerProperties, globalExceptionHandler, clock, metricsService);
		var rowMapper = new JdbcOAuth2AuthorizationService.JsonMapperOAuth2AuthorizationRowMapper(
				registeredClientRepository, jsonMapper);
		var paramMapper = new JdbcOAuth2AuthorizationService.JsonMapperOAuth2AuthorizationParametersMapper(
				jsonMapper);
		authorizationService.setAuthorizationRowMapper(rowMapper);
		authorizationService.setAuthorizationParametersMapper(paramMapper);
		return authorizationService;
	}

	@Bean
	@ConditionalOnBooleanProperty(value = "trustbroker.config.servermultiprocessed", havingValue = false)
	public InMemoryOAuth2AuthorizationService authorizationServiceDev() {
		return new InMemoryOAuth2AuthorizationService();
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder()
				.issuer(oidcProperties.getIssuer())
				.build();
	}

}
