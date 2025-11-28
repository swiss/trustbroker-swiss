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

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import swiss.trustbroker.api.homerealmdiscovery.attributes.HrdClaimsProviderToRelyingPartyMapping;

/**
 * Configuration for CP mapped to an RP.
 *
 * @see swiss.trustbroker.api.homerealmdiscovery.service.HrdService
 */
@XmlRootElement(name = "ClaimsProvider")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClaimsProvider implements Serializable, HrdClaimsProviderToRelyingPartyMapping {

	/**
	 * References the issuer ID of the CP.
	 */
	@XmlAttribute(name = "id")
	private String id;

	/**
	 * Allow pre-configuration of ClaimsProviderMappings with enabled or disabled ClaimsParty in profiles and only pick
	 * them per relying party in setup.
	 * Default: Unset value signals an enabled claims party and ignoring entries with the same id in the profile.
	 *
	 * @since 1.9.0
	 */
	@XmlAttribute(name = "enabled")
	private Boolean enabled;

	/**
	 * A comma separated list of network identifiers. When computing the HRD screen the incoming loadbalancer HTTP Header
	 * Client_Network (is considered to filter out CPs that are not defined on the incoming network, mainly:
	 * <ul>
	 *     <li>INTRANET (intranet)</li>
	 *     <li>INTERNET (external networks)</li>
	 * </ul>
	 */
	@XmlAttribute(name = "clientNetworks")
	private String clientNetworks;

	/**
	 * By providing a relying party ID on the HRD declaration, it's not necessary anymore to copy and paste entire RP
	 * definition files just to be able to automatically selecting an RP without showing a HRD selection screen.
	 * The relyingPartyAlias can refer to these three inputs:
	 * <ul>
	 *     <li>SAML AuthnRequest.Issuer ID</li>
	 *     <li>SAML AuthnRequest.ProviderName</li>
	 *     <li>OIDC client_id</li>
	 * </ul>
	 * The HRD entries with a relyingPartyAlias attribute are not shown on the HRD screen but are used to directly dispatch
	 * towards the CP when an RP with this issuer ID comes along.
	 * <br/>
	 * If no alias matches through and no HRD entries without an alias remain, all the tiles are displayed through.
	 */
	@XmlAttribute(name = "relyingPartyAlias")
	private String relyingPartyAlias;

	/**
	 * The HRD hint parameter sent by the RP is matched against the following attributes of the ClaimsProvider element.
	 * <br/>
	 * This allows decoupling the RP configuration from the internal CP ID. If configured, only the alias is checked against
	 * the HRD hint to avoid accidental dependency on the CP ID.
	 * <br/>
	 * The HRD hint is matched against the following <code>ClaimsProvider</code> fields in the given order:
	 * <ol>
	 *     <li>hrdHintAlias</li>
	 *     <li>name</li>
	 *     <li>id</li>
	 * </ol>
	 * Name and/or ID might be URNs, in which case the hrdHintAlias can also help avoiding URL parameter encoding issues.
	 *
	 * @see swiss.trustbroker.config.TrustBrokerProperties#getHrdHintParameter()
	 * @since 1.10.0
	 */
	@XmlAttribute(name = "hrdHintAlias")
	private String hrdHintAlias;

	/**
	 * Show this banner above the HRD selection area if tile is enabled.
	 *
	 * @since 1.9.0
	 */
	@XmlAttribute(name = "banner")
	private String banner;

	/**
	 * Indicates the order of display in the UI. Special values:
	 * <ol>
	 *     <li>less or equal 0 - do not show in UI</li>
	 *     <li>1xx - first priority CPs (displayed larger, ordered numerically)</li>
	 *     <li>2xx - second priority CPs (displayed larger, ordered numerically)</li>
	 *     <li>3xx - third priority CPs (displayed smalled, ordered numerically)</li>
	 * </ol>
	 * Default: ordered of definition in the XML
	 *
	 * @since 1.9.0
	 */
	@XmlAttribute(name = "order")
	private Integer order;

	/**
	 * Name displayed to the user directly.
	 * The XTB SPA frontend uses it to translate the name into a text with the translation service.
	 * The skinny frontend uses the items directly.
	 */
	@XmlAttribute(name = "name")
	private String name;

	/**
	 * Title for the CP tile and help item.
	 * <br/>
	 * The fallback order (if not defined) is: title > name > ID
	 */
	@XmlAttribute(name = "title")
	private String title;

	/**
	 * Text displayed in the CP tile.
	 * <br/>
	 * The fallback order (if not defined) is: description > name > ID
	 */
	@XmlAttribute(name = "description")
	private String description;

	/**
	 * Image displayed in the HRD large view.
	 */
	@XmlAttribute(name = "img")
	private String img;

	/**
	 * Image displayed in the small view. This feature was removed and replaced by shortcut/color rendering.
	 * The small view was dropped in v1.5.
	 *
	 * @deprecated remove
	 */
	@Deprecated(since = "1.10.0", forRemoval = true)
	@XmlAttribute(name = "button")
	private String button;

	/**
	 * A usually two-character code identifying the CP on small screens.
	 */
	@XmlAttribute(name = "shortcut")
	private String shortcut;

	/**
	 * HTML color code identifying the CP on small screens.
	 */
	@XmlAttribute(name = "color")
	private String color;

	public final boolean isValidForNetwork(String network) {
		return network == null
				|| clientNetworks == null
				|| clientNetworks.contains(network);
	}

	public final boolean isMatchingRelyingPartyAlias(String rpIssuer) {
		return relyingPartyAlias != null && relyingPartyAlias.equals(rpIssuer);
	}

	public static ClaimsProvider of(HrdClaimsProviderToRelyingPartyMapping mapping) {
		if (mapping instanceof ClaimsProvider cpRp) {
			return cpRp;
		}
		if (mapping == null) {
			return null;
		}
		return ClaimsProvider.builder()
							 .id(mapping.getId())
							 .clientNetworks(mapping.getClientNetworks())
							 .relyingPartyAlias(mapping.getRelyingPartyAlias())
							 .build();
	}

	@JsonIgnore
	public boolean isDisplayed() {
		// Old HRD config does not use order and CPs with alias are never displayed
		return (order == null || order > 0);
	}

	@JsonIgnore
	public boolean isEnabledAndValid() {
		return (this.enabled == null || enabled)
				&& id != null;
	}

	// HRD hint matching order: alias > name > id
	@JsonIgnore
	public boolean isMatchingHrdHint(String cpSelectionHint) {
		if (cpSelectionHint == null) {
			return false;
		}
		return cpSelectionHint.equals(hrdHintAlias)
				|| cpSelectionHint.equals(name)
				|| cpSelectionHint.equals(id);
	}

}
