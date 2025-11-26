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

import java.util.Collections;
import java.util.List;
import javax.annotation.Nonnull;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import org.opensaml.security.credential.Credential;
import swiss.trustbroker.common.exception.TechnicalException;

/**
 * This class describes the configuration of a claims provider (CP).
 * <br/>
 * Note on the name: The ClaimsProvider class is already taken
 * for the HRD configuration, and we do not (yet) want to merge those two classes into one,
 * because the want to reuse the ClaimsProviderDefinitions that also contain
 * ClaimsProvider configurations but mainly for the UI display.
 * So we name this class ClaimsParty, a mix of 'Asserting Party' (the counterpart of the 'RelyingParty') and the
 * ClaimsProvider we would want to use ending up in the shortcut CP again.
 *
 * @see ClaimsProviderDefinitions
 * @see ClaimsProviderMappings
 */
@XmlRootElement(name = "ClaimsParty")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@EqualsAndHashCode(callSuper=true)
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
public class ClaimsParty extends CounterParty {

	/**
	 * Issuer ID of the claims provider that need to match ClaimsProvider entries in ClaimsProviderDefinitions for HRD display
	 * and have to be returned by CPs in SAML responses.
	 */
	@XmlAttribute(name = "id")
	private String id;

	@XmlAttribute(name = "enabled")
	@Builder.Default
	private FeatureEnum enabled = FeatureEnum.TRUE;

	/**
	 * This flag allows to disable setting the AssertionConsumerServiceURL in the AuthnRequest towards the CP as some CPs
	 * do fail when it is set (correctly or incorrectly).
	 */
	@XmlAttribute(name = "disableACUrl")
	@Builder.Default
	private Boolean disableACUrl = Boolean.FALSE;

	/**
	 * This status policy determines the handling of users that are not found in the IDM:
	 * BLOCK_UNKNOWN_USER, ALLOW_UNKNOWN_USER.
	 *
	 * @see StatusPolicy#BLOCK_UNKNOWN_USER
	 * @see StatusPolicy#ALLOW_UNKNOWN_USER
	 */
	@XmlAttribute(name = "statusPolicy")
	private StatusPolicy statusPolicy;

	/**
	 * Enable IDM provisioning based on CP response.
	 * <br/>
	 * Consider using the newer <code>Provisioning.enabled</code> instead.
	 * <br/>
	 * Default: FALSE
	 *
	 * @since 1.9.0
	 * @see Provisioning
	 */
	@XmlAttribute(name = "provision")
	private ProvisioningMode provision;

	/**
	 * Configure what QoA the CP can deliver per default, e.g. weak, normal or strong. See XTB Single Sign On (SSO, SLO)
	 * on how QoA is handled in the context of XTB.
	 */
	@XmlElement(name = "AuthLevel")
	private String authLevel;

	/**
	 * This attribute allows to map a QoA of <pre>StrongestPossible</pre> on the message level to a corresponding real QoA
	 * level to handle XTB Single Sign On (SSO, SLO) as this QoA value does not represent a real QoA.
	 * <br/>
	 * Fallback: authLevel
	 */
	@XmlElement(name = "StrongestPossibleAuthLevel")
	private String strongestPossibleAuthLevel;

	/**
	 * The homeName is usually consumed from the home name attribute and identifies the CP attribute to consume the CP
	 * identity from instead of the subject name ID source.
	 * <br/>
	 * If not specified or not provided by CP the SAML Response Subject NameID is sued.
	 */
	@XmlElement(name = "HomeName")
	private HomeName homeName;

	/**
	 * The Account Source consumed by the <code>IdmProvisioningService<code>
	 * @since 1.12.0
	 */
	@XmlElement(name = "AccountSource")
	private AccountSource accountSource;

	/**
	 * The original issuer is by default consumed as is and not changed in the CP handling of XTB.
	 * <br/>
	 * Fallback: id
	 */
	@XmlElement(name = "OriginalIssuer")
	private String originalIssuer;

	/**
	 * Override of the global issuer for this CP.
	 */
	@XmlElement(name = "AuthnRequestIssuerId")
	private String authnRequestIssuerId;

	/**
	 * Override ID as expected issuer of CP response.
	 * <br/>
	 * Can be set to decouple the CP response issuer from the ID. The ID of another CP is permitted here in which case the CP used for the request is picked.
	 * <br/>
	 * Fallback: id
	 * @since 1.12.0
	 */
	@XmlElement(name = "ResponseIssuer")
	private String responseIssuer;

	// endpoints

	/**
	 * SAML POST endpoint on the CP.
	 */
	@XmlElement(name = "SSOUrl")
	private String ssoUrl;

	// PKI setup / access control

	/**
	 * You only need to declare SignerTruststore for SAML response verification. For signing the SignerKeystore declared on the
	 * RP side is (re-)used.
	 *
	 * @see RelyingParty#getCertificates()
	 */
	@XmlElement(name = "Certificates", required = true)
	private Certificates certificates;

	/**
	 * Global security policy overrides for this CP.
	 */
	@XmlElement(name = "SecurityPolicies")
	private SecurityPolicies securityPolicies;

	/**
	 * OIDC client configuration to integrate CP/IDP
	 *
 	 * @since 1.9.0
	 */
	@XmlElement(name = "Oidc")
	private Oidc oidc;

	/**
	 * SAML protocol configuration for this CP.
	 */
	@XmlElement(name = "Saml")
	private Saml saml;

	// processing model

	/**
	 * Subject Name ID mappings for this CP.
	 *
	 * @since 1.8.0
	 */
	@XmlElement(name = "SubjectNameMappings")
	private SubjectNameMappings subjectNameMappings;

	/**
	 * QoA configurations for this CP.
	 *
	 * @since 1.9.0
	 */
	@XmlElement(name = "Qoa")
	private Qoa qoa;

	/**
	 * Provisioning configurations for this CP.
	 *
	 * @since 1.12.0
	 */
	@XmlElement(name = "Provisioning")
	private Provisioning provisioning;

	/**
	 * The filtering is done when the SAML response is received from the CP. This element therefore declares, which original
	 * issuer attributes are acceptable for propagation to RPs.
	 *
	 * @see RelyingParty#getAttributesSelection()
	 */
	@XmlElement(name = "AttributesSelection")
	private AttributesSelection attributesSelection;

	/**
	 * Script hooks. Only scripts related to this CP are executed.
	 */
	@XmlElement(name = "Scripts")
	private Scripts scripts;

	// transient because this class is Serializable and Credential is not
	private transient List<Credential> cpTrustCredential;

	private transient List<Credential> cpDecryptionCredentials;

	private transient Credential cpBackendClientCredential;

	private transient List<Credential> cpBackendTrustCredentials;

	// XmlTransient not allowed on transient field (the Javadoc does not say transient is considered XmlTransient)
	@XmlTransient
	public List<Credential> getCpTrustCredential() {
		return cpTrustCredential;
	}

	@XmlTransient
	public List<Credential> getCpDecryptionCredentials() { return cpDecryptionCredentials; }

	// NP safe accessor
	public boolean acUrlDisabled() { return Boolean.TRUE.equals(disableACUrl); }

	public String getOriginalIssuer() {
		return originalIssuer != null ? originalIssuer : id;
	}

	public String getResponseIssuer() {
		return responseIssuer != null ? responseIssuer : id;
	}

	public String getStrongestPossibleAuthLevelWithFallback() {
		if (strongestPossibleAuthLevel != null) {
			return strongestPossibleAuthLevel;
		}
		return authLevel;
	}

	// Pass on rpIssuer to CP in Scoping element - defaults to false (unlike RelyingParty.isDelegateOrigin)
	public boolean isDelegateOrigin() {
		var secPol = getSecurityPolicies();
		return secPol != null && Boolean.TRUE.equals(secPol.getDelegateOrigin());
	}

	public String getAuthnRequestIssuerId(String defaultIssuerId) {
		if (authnRequestIssuerId == null) {
			return defaultIssuerId;
		}
		return authnRequestIssuerId;
	}

	@Nonnull
	@Override
	public String getShortType() {
		return "CP";
	}

	public ProvisioningMode getProvision() {
		if (provision != null) {
			return provision;
		}
		if (provisioning != null) {
			return provisioning.getProvisioning();
		}
		return ProvisioningMode.FALSE;
	}

	/**
	 * @return true if OIDC is to be used towards CP
	 */
	public boolean useOidc() {
		return oidc != null;
	}

	/**
	 * @return true if SAML is to be used towards CP
	 */
	public boolean useSaml() {
		return !useOidc(); // SAML is the default
	}

	@XmlTransient
	public OidcClient getSingleOidcClient() {
		if (oidc == null) {
			throw new TechnicalException(String.format("Invalid ClaimsParty id=%s (missing OidcClient)", id));
		}
		var oidcClientCount = oidc.getClients().size();
		if (oidcClientCount != 1) {
			throw new TechnicalException(String.format("Invalid ClaimsParty id=%s expected single OidcClient, but count=%s",
					id, oidcClientCount));
		}
		return oidc.getClients().get(0);
	}

	public List<OidcClient> getOidcClients() {
		return oidc != null && oidc.getClients() != null ? oidc.getClients() : Collections.emptyList();
	}

}
