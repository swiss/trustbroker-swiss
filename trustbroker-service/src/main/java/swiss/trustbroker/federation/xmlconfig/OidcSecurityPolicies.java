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

package swiss.trustbroker.federation.xmlconfig;

import java.io.Serializable;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Security policy overrides for OIDC.
 */
@XmlRootElement(name = "OidcSecurityPolicies")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OidcSecurityPolicies implements Serializable {

	/**
	 * Require Proof Key for Code Exchange (PKCE).
	 * <br/>
	 * Default: true
	 */
	@XmlAttribute(name = "requireProofKey")
	@Default(value = "true")
	private Boolean requireProofKey;

	/**
	 * Require authorization consent (currently unsupported).
	 * <br/>
	 * Default: false
	 */
	@XmlAttribute(name = "requireAuthorizationConsent")
	@Default(value = "false")
	private Boolean requireAuthorizationConsent;

	/**
	 * Allow to enable Opaque AccessToken for Rp.
	 * <br/>
	 * Default: false
	 *
	 * @since 1.11.0
	 */
	@XmlAttribute(name = "requireOpaqueAccessToken")
	@Default(value = "false")
	private Boolean requireOpaqueAccessToken;

	/**
	 * Allow access_token in form body
	 * <br/>
	 * Default: false
	 *
	 * @since 1.14.0
	 */
	@XmlAttribute(name = "allowFormBearerToken")
	@Default(value = "false")
	private Boolean allowFormBearerToken;

	/**
	 * Allow to enable Encrypted IdToken JWT Singing for Rp.
	 * <br/>
	 * Default: false
	 *
	 * @since 1.11.0
	 */
	@XmlAttribute(name = "requireIdTokenEncryption")
	@Default(value = "false")
	private Boolean requireIdTokenEncryption;

	/**
	 * Allow to enable Opaque RefreshToken for Rp.
	 * <br/>
	 * Default: false
	 *
	 * @since 1.11.0
	 */
	@XmlAttribute(name = "requireOpaqueRefreshToken")
	@Default(value = "false")
	private Boolean requireOpaqueRefreshToken;

	/**
	 * Allow to enable Encrypted UserInfo response
	 * <br/>
	 * Default: false
	 *
	 * @since 1.11.0
	 */
	@XmlAttribute(name = "requireUserInfoResponseEncryption")
	@Default(value = "false")
	private Boolean requireUserInfoResponseEncryption;

	/**
	 * Encryption algorithm
	 * <br/>
	 * Default: RSA-OAEP-256
	 *
	 * @since 1.11.0
	 */
	@XmlAttribute(name = "encryptionAlgorithm")
	@Default(value = "RSA-OAEP-256") // JWEAlgorithm.RSA_OAEP_256
	private String encryptionAlgorithm;

	/**
	 * Encryption method
	 * <br/>
	 * Default: A256GCM
	 *
	 * @since 1.11.0
	 */
	@XmlAttribute(name = "encryptionMethod")
	@Default(value = "A256GCM") // EncryptionMethod.A256GCM
	private String encryptionMethod;

	/**
	 * Encryption keyID
	 *
	 * @since 1.11.0
	 */
	@XmlAttribute(name = "encryptionKid")
	private String encryptionKid;

	/**
	 * Token validity in minutes.
	 */
	@XmlAttribute(name = "tokenTimeToLiveMin")
	private Integer tokenTimeToLiveMin;

	/**
	 * Overrides tokenTimeToLiveMin for the access token.
	 */
	@XmlAttribute(name = "accessTokenTimeToLiveMin")
	private Integer accessTokenTimeToLiveMin;

	/**
	 * Overrides tokenTimeToLiveMin for the ID token.
	 */
	@XmlAttribute(name = "idTokenTimeToLiveMin")
	private Integer idTokenTimeToLiveMin;

	/**
	 * Overrides tokenTimeToLiveMin for the refresh token.
	 */
	@XmlAttribute(name = "refreshTokenTimeToLiveMin")
	private Integer refreshTokenTimeToLiveMin;

	/**
	 * Overrides tokenTimeToLiveMin for the authorization code.
	 */
	@XmlAttribute(name = "authorizationCodeTimeToLiveMin")
	private Integer authorizationCodeTimeToLiveMin;

	/**
	 * Allow to invalidate OIDC sessions before token TTL, keep for 1 minute to allow login sequence termination.
	 * <br/>
	 * Default: 1
	 */
	@XmlAttribute(name = "sessionTimeToLiveMin")
	@Default(value = "1")
	private Integer sessionTimeToLiveMin;

	/**
	 * Reuse refresh tokens.
	 * <br/>
	 * Default: false
	 *
	 */
	@XmlAttribute(name = "reuseRefreshTokens")
	@Default(value = "false")
	private Boolean reuseRefreshTokens;

	/**
	 * ID token signature algorithm (many adapters only support RS256)
	 */
	@XmlAttribute(name = "idTokenSignature")
	private String idTokenSignature;

	/**
	 * Controls the OIDC session cookies sameSite flag None, Strict, Dynamic.
	 * Dynamic: Choose None or Strict based on whether the involved URLs are same site or not.
	 * (A value of Lax while valid has no benefits over Strict and is too restrictive for cross-domain use.)
	 * <br/>
	 * Default: Dynamic
	 */
	@XmlAttribute(name = "sessionCookieSameSite")
	@Default(value = "Dynamic") // WebUtil.COOKIE_SAME_SITE_DYNAMIC
	private String sessionCookieSameSite;

	public Integer getAccessTokenTimeToLiveMin() {
		if (accessTokenTimeToLiveMin != null) {
			return accessTokenTimeToLiveMin;
		}
		return tokenTimeToLiveMin;
	}

	public Integer getIdTokenTimeToLiveMin() {
		if (idTokenTimeToLiveMin != null) {
			return idTokenTimeToLiveMin;
		}
		return tokenTimeToLiveMin;
	}

	/**
	 * Allow Token Exchange with Public Client
	 * <br/>
	 * Default: false
	 *
	 * @since 1.14.0
	 */
	@XmlAttribute(name = "allowPublicClientTokenExchange")
	@Default(value = "false")
	private Boolean allowPublicClientTokenExchange;

	/**
	 * Restrict Token Exchange subject_token age
	 * <br/>
	 * Default: 60
	 *
	 * @since 1.14.0
	 */
	@XmlAttribute(name = "subjectTokenMaxAgeSec")
	@Default(value = "60")
	private Integer subjectTokenMaxAgeSec;

	/**
	 * Maximum number a subject_token can be used
	 * <br/>
	 * Default: 1
	 *
	 * @since 1.14.0
	 */
	@XmlAttribute(name = "subjectTokenMaxUseCount")
	@Default(value = "1")
	private Integer subjectTokenMaxUseCount;

	/**
	 * subject_token timestamp clock/transfer tolerance.
	 *
	 * @since 1.14.0
	 */
	@XmlAttribute(name = "subjectTokenNotOnOrAfterToleranceSec")
	private Integer subjectTokenNotOnOrAfterToleranceSec;

	/**
	 * subject_token tolerance NTP drift tolerance.
	 *
	 * @since 1.14.0
	 */
	@XmlAttribute(name = "subjectTokenNotBeforeToleranceSec")
	private Integer subjectTokenNotBeforeToleranceSec;

	/**
	 * Restrict client_assertion age
	 * <br/>
	 * Default: 60
	 *
	 * @since 1.14.0
	 */
	@XmlAttribute(name = "clientAssertionMaxAgeSec")
	@Default(value = "60")
	private Integer clientAssertionMaxAgeSec;

	/**
	 * Restrict client_assertion expiration maxLifeTime
	 * <br/>
	 * Default: 3600 (1h)
	 *
	 * @since 1.14.0
	 */
	@XmlAttribute(name = "clientAssertionExpirationLifeTimeSec")
	@Default(value = "3600")
	private Integer clientAssertionExpirationLifeTimeSec;

	/**
	 * client_assertion timestamp clock/transfer tolerance.
	 *
	 * @since 1.14.0
	 */
	@XmlAttribute(name = "clientAssertionNotOnOrAfterToleranceSec")
	private Integer clientAssertionNotOnOrAfterToleranceSec;

	/**
	 * client_assertion tolerance NTP drift tolerance.
	 *
	 * @since 1.14.0
	 */
	@XmlAttribute(name = "clientAssertionNotBeforeToleranceSec")
	private Integer clientAssertionNotBeforeToleranceSec;
}
