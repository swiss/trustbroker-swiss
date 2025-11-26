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

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlValue;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Groovy script hook configuration. The following script hooks are supported:
 * <ul>>
 *     <li>OnRequest: Inbound validation hook on RP request</li>
 *     <li>BeforeHrd: Allows to pre-select programmatically a CP based on RP information and network topology
 *     parameters (access to HTTP request layer according to J2EE servlet API).</li>
 *     <li>OnCpRequest: Outbound hook on CP request.</li>
 *     <li>BeforeIdm: On both sides of the federation (CP and RP) this hook is called before the IDM services are invoked.</li>
 *     <li>AfterIdm: On RP side of the federation these hooks are called after IDM related data collection and
 *     before calling access request and assembling and filtering the RP assertion attributes.</li>
 *     <li>OnResponse: This script is called just before assembling and signing SAML assertion.</li>
 *     <li>OnUserInfo: On OIDC user info request</li>
 *     <li>OnToken: This script is called just before assembling and signing OIDC tokens.</li>
 * </ul>
 * The following beans are passed to the scripts, some depending on the hook:
 * <ul>
 *     <li>LOG: SLF4J Logger</li>
 *     <li>HTTPRequest: Jakarta HttpServletRequest</li>
 *     <li>RPRequest: XTB RpRequest</li>
 *     <li>CPResponse: XTB CpResponse</li>
 *     <li>SAMLResponse: OpenSAML Response</li>
 *     <li>SAMLRequest: OpenSAML RequestAbstractType</li>
 *     <li>IDMQueryList: List of XTB IdmQuery executed</li>
 *     <li>RPConfig: XTB RelyingPartySetupService</li>
 *     <li>ClaimValues: List of Object values for OIDC value conversion</li>
 * </ul>
 */
@XmlRootElement(name = "Script")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Script implements Serializable {

	/**
	 * Script types as listed above.
	 */
	@XmlAttribute(name="type")
	private String type;

	/**
	 * The value identifies the script stored in the trustbroker-inventories definition/scripts directory.
	 */
	@XmlValue
	private String name;
}
