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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
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
import org.apache.commons.collections.ListUtils;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.security.credential.Credential;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.dto.SignatureParameters;

/**
 * This class describes the configuration of a relying party (RP).
 * <br/>
 * The following sources of attributes to be passed to the RP exist:
 * <ul>
 *     <li>Attributes definitions (from CP)</li>
 * 	   <li>UserDetails definitions (from IDM)</li>
 * 	   <li>Properties definitions (computed by XTB or in Scripts)</li>
 * </ul>
 * <br/>
 * RP profiles are configuration templates for RP setups that reflect a common pattern used by multiple RPs.
 * <br/>
 * Potentially breaking changes: see <code>FeatureEnum</code>
 */
@XmlRootElement(name = "RelyingParty")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@EqualsAndHashCode(callSuper=true)
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@SuppressWarnings("java:S6539") // the main configuration class containing quite a number of sub elements, hence many references
public class RelyingParty extends CounterParty implements RelyingPartyConfig {

	@XmlAttribute(name = "id")
	private String id;

	@XmlTransient
	private String unaliasedId;

	/**
	 * Flag to enable/disable this RP.
	 * <br/>
	 * Default is true.
	 */
	@XmlAttribute(name = "enabled")
	@Builder.Default
	private FeatureEnum enabled = FeatureEnum.TRUE;

	@XmlAttribute(name = "base")
	private String base;

	/**
	 * ClientName is the access tenant identifier (somewhat a short form of the relying party ID)
	 * applied to all <pre>%clientname%</pre> placeholders in the configuration, specifically the attributes as listed
	 * above.
	 */
	@XmlElement(name = "ClientName")
	private String clientName;

	/**
	 * If the SAML ProviderName or OIDC client_id are wrong or missing, a relying party can be configured with a global
	 * ApplicationName used for AccessRequest ProfileSelection or AnnouncementService to select the matching data items.
	 *
	 * 	@since 1.12.0
	 */
	@XmlElement(name = "ApplicationName")
	private String applicationName;

	/**
	 * We introduce the billing field, so we can start make some trials adding it to the config. We might need to move it
	 * to the access request application section later if RP-ID is not 1:1 related to billingId.
	 * The value is currently only used in the XTB auditing.
	 */
	@XmlElement(name = "BillingId")
	private String billingId;

	/**
	 * Primary key of the IDM client identifying an access tenant.
	 */
	@XmlElement(name = "ClientExtId")
	private String clientExtId;

	// endpoints

	/**
	 * Assertion consumer service URL authorized to access XTB federation services for this RP.
	 */
	@XmlElement(name = "ACWhitelist")
	private AcWhitelist acWhitelist;

	// access control

	/**
	 * For verification and signing. For signing the SignerKeystore declared on is (re-)used on the CP side.
	 *
	 * @see ClaimsParty#getCertificates()
	 */
	@XmlElement(name = "Certificates", required = false)
	private Certificates certificates;

	/**
	 * Global security policy overrides for this RP.
	 */
	@XmlElement(name = "SecurityPolicies")
	private SecurityPolicies securityPolicies;

	/**
	 * OIDC client configuration for this RP.
	 */
	@XmlElement(name = "Oidc")
	private Oidc oidc;

	/**
	 * SAML protocol configuration for this RP.
	 */
	@XmlElement(name = "Saml")
	private Saml saml;

	// feature flags

	/**
	 * Announcement configuration for this RP.
	 */
	@XmlElement(name = "Announcements")
	private AnnouncementRpConfig announcement;

	/**
	 * SSO configuration for this RP.
	 */
	@XmlElement(name = "SSO")
	private Sso sso;

	// HRD

	/**
	 * List of CPs mapped to this RP.
	 */
	@XmlElement(name = "ClaimsProviderMappings")
	private ClaimsProviderMappings claimsProviderMappings;

	/**
	 * Subject Name ID mappings for this RP.
	 */
	@XmlElement(name = "SubjectNameMappings")
	private SubjectNameMappings subjectNameMappings;

	// processing model

	/**
	 * QoA configurations for this RP.
	 */
	@XmlElement(name = "Qoa")
	private Qoa qoa;

	/**
	 * Error flow policies for this RP.
	 */
	@XmlElement(name = "FlowPolicies")
	private FlowPolicies flowPolicies;

	/**
	 * AccessRequest configuration for this RP.
	 */
	@XmlElement(name = "AccessRequest")
	private AccessRequest accessRequest;

	/**
	 * RP side attribute selection.
	 *
	 * @see ClaimsParty#getAttributesSelection()
	 */
	@XmlElement(name = "AttributesSelection")
	private AttributesSelection attributesSelection;

	/**
	 * Constant attributes to be added for this RP.
	 * @deprecated replaced with ClaimsSelection
	 */
	@Deprecated(since = "1.9.0", forRemoval = true)
	@XmlElement(name = "ConstAttributes")
	private ConstAttributes constAttributes;

	/**
	 * IDM lookup configuration for this RP.
	 */
	@XmlElement(name = "IDMLookup")
	private IdmLookup idmLookup;

	/**
	 * Properties selection identifies the computed/derived attributes passed through to the RP.
	 */
	@XmlElement(name = "PropertiesSelection")
	private AttributesSelection propertiesSelection;

	/**
	 * RP side claims selection.
	 *
	 * @since 1.9.0
	 */
	@XmlElement(name = "ClaimsSelection")
	private AttributesSelection claimsSelection;

	/**
	 * Profile selection configuration for this RP.
	 */
	@XmlElement(name = "ProfileSelection")
	private ProfileSelection profileSelection;

	/**
	 * Script hooks. Only scripts related to this RP are executed.
	 */
	@XmlElement(name = "Scripts")
	private Scripts scripts;

	// cached configs

	private transient List<Credential> rpTrustCredentials;

	private transient Credential rpSigner;

	private transient Credential rpEncryptionTrustCredential;

	private transient List<Credential> rpDecryptionCredentials;

	// Lombok would generate these, but schemagen compilation complains about not implementing RelyingPartyConfig / CounterParty

	@Override
	public String getId() {
		return id;
	}

	@Override
	public FeatureEnum getEnabled() {
		return enabled;
	}

	@Override
	public void setEnabled(FeatureEnum enabled) {
		this.enabled = enabled;
	}

	@Override
	public SubjectNameMappings getSubjectNameMappings() {
		return subjectNameMappings;
	}

	@Override
	public SecurityPolicies getSecurityPolicies() { return securityPolicies; }

	@Override
	public Saml getSaml() {
		return saml;
	}

	@Override
	public AttributesSelection getAttributesSelection() { return attributesSelection; }

	@Override
	public Scripts getScripts() {
		return scripts;
	}

	@Override
	public Qoa getQoa() {
		return qoa;
	}

	@Override
	public Certificates getCertificates() {
		return certificates;
	}

	public OidcClient getSingleOidcClient() {
		if (oidc == null) {
			throw new TechnicalException(String.format("Invalid RelyingParty id=%s (missing OidcClient)", id));
		}
		var oidcClientCount = oidc.getClients().size();
		if (oidcClientCount != 1) {
			throw new TechnicalException(String.format("Invalid RelyingParty id=%s expected single OidcClient, but count=%s",
					id, oidcClientCount));
		}
		return oidc.getClients().get(0);
	}

	// XmlTransient not allowed on transient fields (the Javadoc does not say transient is considered XmlTransient):

	@XmlTransient
	public List<Credential> getRpTrustCredentials() {
		return rpTrustCredentials;
	}

	@XmlTransient
	public Credential getRpSigner() {
		return rpSigner;
	}

	@XmlTransient
	public Credential getRpEncryptionTrustCredential() {
		return rpEncryptionTrustCredential;
	}

	// derived

	public boolean isSsoEnabled() {
		return sso != null && sso.isEnabled();
	}

	public Optional<String> getSloUrl(SloProtocol protocol) {
		if (sso == null) {
			return Optional.empty();
		}
		// 1. use SLO URL attribute for SAML2 only (we might get rid of that attribute)
		if (protocol == SloProtocol.SAML2 && StringUtils.isNotEmpty(sso.getSloUrl())) {
			return Optional.of(sso.getSloUrl());
		}
		// 2. find a matching SloUrl element for RESPONSE for protocol
		return sso.getSloResponse().stream()
				.filter(slo -> slo.hasSloUrlForResponse(protocol)).map(SloResponse::getUrl)
				.findFirst();
	}

	public Optional<String> getSloIssuer(SloProtocol protocol) {
		if (sso == null) {
			return Optional.empty();
		}
		return sso.getSloResponse().stream()
				.filter(slo -> slo.hasIssuerForResponse(protocol)).map(SloResponse::getIssuer)
				.findFirst();
	}

	public List<OidcClient> getOidcClients() {
		return oidc != null && oidc.getClients() != null ? oidc.getClients() : Collections.emptyList();
	}

	public Saml initializedSaml() {
		if (saml == null) {
			saml = new Saml();
		}
		return saml;
	}

	@Override
	public SignatureParameters.SignatureParametersBuilder getSignatureParametersBuilder() {
		var builder = super.getSignatureParametersBuilder();
		return builder.credential(getRpSigner());
	}

	// disable setting OriginalIssuer on Attribute - defaults to true (unlike ClaimsParty.isDelegateOrigin)
	public boolean isDelegateOrigin() {
		var secPol = getSecurityPolicies();
		return secPol == null || secPol.getDelegateOrigin() == null ||
				secPol.getDelegateOrigin();
	}

	public List<Flow> getFlows() {
		return (flowPolicies != null && flowPolicies.enabled()) ?
				flowPolicies.getFlows() : Collections.emptyList();
	}

	public boolean sameHrd(RelyingParty relyingParty) {
		if (this.claimsProviderMappings == null || relyingParty.claimsProviderMappings == null) {
			return false;
		}
		return ListUtils.isEqualList(this.claimsProviderMappings.getClaimsProviderList(),
				relyingParty.claimsProviderMappings.getClaimsProviderList());
	}

	public Optional<ClaimsProvider> getCpMappingForAlias(String rpAliasId) {
		if (rpAliasId == null || claimsProviderMappings == null || claimsProviderMappings.getClaimsProviderList() == null) {
			return Optional.empty();
		}
		return claimsProviderMappings.getClaimsProviderList().stream()
				.filter(cpRp -> rpAliasId.equals(cpRp.getRelyingPartyAlias())).findFirst();
	}

	public List<Definition> getAllDefinitions() {
		List<Definition> allDefs = new ArrayList<>();
		addAllDefinitions(attributesSelection, allDefs);
		if (idmLookup != null) {
			idmLookup.getQueries().forEach(
					q -> addAllDefinitions(q.getUserDetailsSelection(), allDefs));
		}
		addAllDefinitions(propertiesSelection, allDefs);
		addAllDefinitions(claimsSelection, allDefs);
		if (constAttributes != null && constAttributes.getAttributeDefinitions() != null) {
			allDefs.addAll(constAttributes.getAttributeDefinitions());
		}
		return allDefs;
	}

	private static void addAllDefinitions(AttributesSelection attributesSelection, List<Definition> allDefs) {
		if (attributesSelection != null && attributesSelection.getDefinitions() != null) {
			allDefs.addAll(attributesSelection.getDefinitions());
		}
	}

	@Nonnull
	@Override
	public String getShortType() {
		return "RP";
	}

	/**
	 * @return true if the RP has Oidc configuration
	 */
	public boolean useOidc() {
		return oidc != null;
	}
}
