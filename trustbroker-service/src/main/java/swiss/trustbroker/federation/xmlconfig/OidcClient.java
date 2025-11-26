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

package swiss.trustbroker.federation.xmlconfig;

import java.io.Serializable;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.commons.collections.CollectionUtils;
import org.opensaml.security.credential.Credential;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import swiss.trustbroker.common.util.UrlAcceptor;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.mapping.dto.QoaConfig;
import swiss.trustbroker.oidc.OidcSecurityConfiguration;

/**
 * OIDC client application configuration.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core</a>
 */
@XmlRootElement(name = "Client")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OidcClient implements Serializable {

	/**
	 * Client ID.
	 */
	@XmlAttribute(name = "id")
	private String id;

	/**
	 * Federation ID override.
	 * <br/>
	 * Fallback to RP ID.
	 */
	@XmlAttribute(name = "federationId")
	private String federationId;

	/**
	 * CP issuer ID override for <code>iss</code> claim validation.
	 * <br/>
	 * Fallback to CP ID.
	 *
	 * @since 1.10.0
	 */
	@XmlAttribute(name = "issuerId")
	private String issuerId;

	/**
	 * Optional support to be able to map back /oauth2/authorize
	 */
	@XmlAttribute(name = "realm")
	private String realm;

	/**
	 * Legacy Policy Enforcement Point (PEP) QOA mapping policy.
	 * <br/>
	 * Fallback: Global defaultUsePepQoaPolicy
	 */
	@XmlAttribute(name = "usePepQoa")
	private String usePepQoa;

	/**
	 * OpenID endpoints a single CP side OIDC client uses for federated login.
	 *
	 * @since 1.9.0
	 */
	@XmlElement(name = "ProtocolEndpoints")
	private ProtocolEndpoints protocolEndpoints;

	/**
	 * Permitted redirect URLs for this client.
	 */
	@XmlElement(name = "RedirectUris")
	private AcWhitelist redirectUris;

	/**
	 * Required for JWT encryption
	 *
	 */
	@XmlElement(name = "Certificates", required = false)
	private Certificates certificates;

	/**
	 * You can encode the secret with one of the supported encoders.
	 * See the provided example <code>EncodePassword.groovy</code> for how to encode a password using Argon2.
	 *
	 * @see OidcSecurityConfiguration#passwordEncoder()
	 */
	@XmlElement(name = "ClientSecret")
	private String clientSecret;

	/**
	 * Override security policies.
	 */
	@XmlElement(name = "OidcSecurityPolicies")
	@Builder.Default
	private OidcSecurityPolicies oidcSecurityPolicies = new OidcSecurityPolicies();

	/**
	 * Authorization grant types to be allowed.
	 * <br/>
	 * Default: authorization_code, refresh_token
	 */
	@XmlElement(name = "AuthorizationGrantTypes")
	private AuthorizationGrantTypes authorizationGrantTypes;

	/**
	 * Client authentication methods to be allowed.
	 * <br/>
	 * Default: none, client_secret_basic, client_secret_post
	 */
	@XmlElement(name = "ClientAuthenticationMethods")
	private ClientAuthenticationMethods clientAuthenticationMethods;

	/**
	 * OIDC scopes to be used.
	 * <br/>
	 * Default: openid, profile, email, address, phone
	 */
	@XmlElement(name = "Scopes")
	private Scopes scopes;

	/**
	 * Response mode to be requested from CP.
	 * <br/>
	 * Default: form_post
	 * @since 1.10.0
	 */
	@XmlElement(name = "ResponseMode")
	@Builder.Default
	private ResponseMode responseMode = ResponseMode.FORM_POST;

	// attributes for 1:n handling of OIDC clients to relying-parties, see RelyingParty class

	/**
	 * QoAs to use.
	 */
	@XmlElement(name = "Qoa")
	private Qoa qoa;

	/**
	 * Attribute selection applied to the claims.
	 */
	@XmlElement(name = "ClaimsSelection")
	private AttributesSelection claimsSelection;

	/**
	 * Sources of claims for OIDC CPs.
	 * <br/>
	 * Default: id_token
	 * @since 1.10.0
	 */
	@XmlElement(name = "ClaimsSources")
	@Builder.Default
	private OidcClaimsSources claimsSources = OidcClaimsSources.builder()
															   .claimsSourceList(List.of(OidcClaimsSource.ID_TOKEN))
															   .build();

	@JsonIgnore
	@XmlTransient
	private RegisteredClient registeredClient;

	private transient Credential clientEncryptionCredential;

	public boolean isValidRedirectUri(String requestedRedirectUri) {
		return redirectUris != null &&
				UrlAcceptor.isRedirectUrlOkForAccess(requestedRedirectUri, redirectUris.getAcNetUrls());
	}

	public boolean isValidRedirectUris(List<String> requestedRedirectUris) {
		return redirectUris != null && requestedRedirectUris != null &&
				requestedRedirectUris.stream()
									 .anyMatch(u -> UrlAcceptor.isRedirectUrlOkForAccess(u, redirectUris.getAcNetUrls()));
	}

	// Best effort accepting Origin not considering port or protocol details against redirects URIs from config.
	// We might match a bit too much in the DEV localhost configuration but that's ok.
	public boolean isTrustedOrigin(String origin) {
		var host = WebUtil.getUrlHost(origin);
		return host != null && redirectUris != null && redirectUris.findFirst(String::contains, host).isPresent();
	}

	public boolean isSameRealm(String incomingRealm) {
		return (realm == null && incomingRealm == null) // site working without realms
				|| (realm != null && realm.equals(incomingRealm)); // site working with realms
	}

	public QoaConfig getQoaConfig() {
		return new QoaConfig(getQoa(), getId());
	}

	public boolean hasScopes() {
		return scopes != null && CollectionUtils.isNotEmpty(scopes.getScopeList());
	}

	public boolean useClaimsFromSource(OidcClaimsSource claimsSource) {
		return claimsSources.getClaimsSourceList().contains(claimsSource);
	}
}
