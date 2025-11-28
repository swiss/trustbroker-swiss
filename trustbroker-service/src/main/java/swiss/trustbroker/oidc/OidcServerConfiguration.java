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

import java.time.Clock;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.exception.GlobalExceptionHandler;
import swiss.trustbroker.metrics.service.MetricsService;
import swiss.trustbroker.oidc.jackson.ObjectMapperFactory;
import swiss.trustbroker.oidc.pkce.PublicClientRefreshTokenAuthenticationConverter;
import swiss.trustbroker.oidc.pkce.PublicClientRefreshTokenAuthenticationProvider;
import swiss.trustbroker.script.service.ScriptService;

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
			SessionRegistry sessionRegistry, HttpSecurity http, OAuth2AuthorizationService authorizationService, JwtDecoder jwtDecoder, JWKSource<SecurityContext> jwkSource) throws Exception {

		// setup spring-authorization-server for login federation
		var authServerConfigurer = new OAuth2AuthorizationServerConfigurer();

		// mandatory client authentication functionality (client login required for /authorize, /token, /introspect, ...)
		authServerConfigurer.clientAuthentication(clientAuthentication -> clientAuthentication
				.authenticationConverters(converters ->
						converters.add(new PublicClientRefreshTokenAuthenticationConverter()))
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
				.errorResponseHandler(new CustomFailureHandler(
						"token", relyingPartyDefinitions, trustBrokerProperties)));

		// optional /introspect (investigate token) and /userinfo endpoints
		if (oidcProperties.isIntrospectionEnabled()) {
			authServerConfigurer.tokenIntrospectionEndpoint(introspectEndpoint -> introspectEndpoint
					.authenticationProvider(new CustomTokenIntrospectionAuthenticationProvider(
							registeredClientRepository, authorizationService))
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
					.requestMatchers(antMatcher("/favicon.ico"), antMatcher("/failure"))
					.permitAll() // skip these
					.anyRequest()
					.authenticated() // protect everything else
			)
			.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
			.with(authServerConfigurer, Customizer.withDefaults());

		// Redirect to the login page when not authenticated from the authorization endpoint
		http.exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(entryPoint(relyingPartyDefinitions)));

		return http.build();
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
		DefaultBearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();
		if (trustBrokerProperties.getOidc() != null && trustBrokerProperties.getOidc().isTokenInRequestBodyEnabled()) {
			bearerTokenResolver.setAllowFormEncodedBodyParameter(true);
		}
		return bearerTokenResolver;
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
			OidcConfigurationUtil.addOptionalClaimToProviderConfiguration(providerConfiguration,
					OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED,
					oidcProperties.getIntrospectionEndpointAuthMethods());
			OidcConfigurationUtil.addOptionalClaimToProviderConfiguration(providerConfiguration,
					OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED,
					oidcProperties.getRevocationEndpointAuthMethods());
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
			OidcConfigurationUtil.addOptionalClaimToProviderConfiguration(providerConfiguration,
					USERINFO_ENCRYPTION_ALG, oidcProperties.getUserInfoEncryptionAlgorithms());
			OidcConfigurationUtil.addOptionalClaimToProviderConfiguration(providerConfiguration,
					USERINFO_ENCRYPTION_METHOD, oidcProperties.getUserInfoEncryptionMethods());
		};
	}

	private Function<OidcUserInfoAuthenticationContext, OidcUserInfo> createUserInfoMapper() {
		return context -> {
			var authentication = context.getAuthentication();
			Map<String, Object> claims = new HashMap<>();
			var principal = authentication.getPrincipal();
			var clientId = context.getAuthorization().getRegisteredClientId();
			var clientConfig = relyingPartyDefinitions.getOidcClientConfigById(clientId, trustBrokerProperties);
			if(clientConfig.isEmpty()) {
				throw new TechnicalException("Could not find client config for " + clientId);
			}
			if (principal instanceof JwtAuthenticationToken jwtAuthenticationToken) {
				var tokenClaims = jwtAuthenticationToken.getToken().getClaims();
				claims = OidcUserInfoUtil.filterUnwantedClaims(tokenClaims,
						relyingPartyDefinitions, scriptService, trustBrokerProperties);
			}
			if (principal instanceof BearerTokenAuthentication bearerTokenAuthentication) {
				claims = bearerTokenAuthentication.getTokenAttributes();
			}
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
		var authorizationService = new CustomOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository,
				trustBrokerProperties, globalExceptionHandler, clock, metricsService);
		var rowMapper = new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(registeredClientRepository);
		var oAuth2AuthorizationParametersMapper = new JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper();
		var springSecObjectMapper = ObjectMapperFactory.springSecObjectMapper();
		oAuth2AuthorizationParametersMapper.setObjectMapper(springSecObjectMapper);
		rowMapper.setObjectMapper(springSecObjectMapper);
		authorizationService.setAuthorizationRowMapper(rowMapper);
		authorizationService.setAuthorizationParametersMapper(oAuth2AuthorizationParametersMapper);
		return authorizationService;
	}

	@Bean
	@ConditionalOnProperty(value = "trustbroker.config.serverMultiProcessed", havingValue = "false", matchIfMissing = false)
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
