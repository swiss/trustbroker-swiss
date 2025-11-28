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

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import swiss.trustbroker.common.util.WebUtil;

/**
 * SSO groups are defined per CP as the XTB Single Sign On (SSO, SLO) mechanism separates SSO logins per identity.
 * The SSO group names are referenced by RPs.
 */
@XmlRootElement(name = "SSOGroup")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SsoGroup {

	/**
	 * Mandatory group name. It's recommended to use a consistent naming scheme, e.g.: <pre>SSO-CUSTOMERGROUP-CPNAME</pre>
	 */
	@XmlAttribute(name = "name")
	private String name;

	/**
	 * Time in minutes without any XTB SSO interaction leading to session removal.
	 */
	@XmlAttribute(name = "maxIdleTimeMinutes")
	private int maxIdleTimeMinutes;

	/**
	 * Time in minutes an SSO session exists at most (even though there was interaction where the idle
	 * timeout did not expire yet).
	 */
	@XmlAttribute(name = "maxSessionTimeMinutes")
	private int maxSessionTimeMinutes;

	/**
	 * Time in minutes an RP can access XTB reusing the currently active SSO session without the need to interact with the CP
	 * again on an established SSO session, except when the SAML <pre>AuthnRequest forceAuth="true"</pre>
	 * flag signals an interaction.
	 */
	@XmlAttribute(name = "maxCachingTimeMinutes")
	private int maxCachingTimeMinutes;

	/**
	 * Controls the SSO session cookie <pre>sameSite</pre> flag: None, Strict, Dynamic.
	 * Dynamic: Choose None or Strict based on whether the involved URLs are same site or not.
	 * (A value of Lax while valid has no benefits over Strict and is too restrictive for cross-domain use.)
	 * <br/>
	 * Default: Dynamic
 	 */
	@XmlAttribute(name= "sessionCookieSameSite")
	@Builder.Default
	private String sessionCookieSameSite = WebUtil.COOKIE_SAME_SITE_DYNAMIC;
}
