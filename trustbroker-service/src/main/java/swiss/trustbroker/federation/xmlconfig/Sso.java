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
import java.util.ArrayList;
import java.util.List;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * XTB Single Sign On (SSO, SLO) configuration for an RP.
 * <br/>
 * Note that when turned off you still use the element to declare an sloUrl/SloResponse to send LogoutResponse messages to in
 * case LogoutRequest messages are sent to XTB.
 */
@XmlRootElement(name = "SSO")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Sso implements Serializable {

	/**
	 * Enable this configuration.
	 */
	@XmlAttribute(name = "enabled")
	private boolean enabled;

	/**
	 * Configure a reference to an existing SSOGroup name. The groupName is required when SSO is enabled only.
	 *
	 * @see SsoGroup#getName()
	 */
	@XmlAttribute(name = "groupName")
	private String groupName;

	/**
	 * If an RP already is logged in with the first CP, the HRD screen can be skipped leading to the second participant
	 * automatically joining the detected SSO session for that CP.
	 */
	@XmlAttribute(name = "skipHrdWithSsoSession")
	private Boolean skipHrdWithSsoSession;

	/**
	 * Refresh IDM data for SSO - enable e.g. if an Access Request might be performed outside XTB.
 	 */
	@XmlAttribute(name = "forceIdmRefresh")
	private Boolean forceIdmRefresh;

	/**
	 * Device fingerprint check mode.
	 */
	@XmlAttribute(name = "fingerprintCheck")
	private FingerprintCheck fingerprintCheck;

	/**
	 * Shortcut for <pre>SloResponse</pre> with this URL and defaults otherwise.
	 * Absolute or relative URL as for <pre>SloResponse</pre>
	 *
	 * @see SloResponse
 	 */
	@XmlAttribute(name = "sloUrl")
	private String sloUrl;

	/**
	 * Notify other SSO participants about the ongoing logout. The participants need to have their notification
	 * endpoints configured using SloResponse elements.
	 * <br/>
	 * Potentially breaking changes:
	 * <ul>
	 *     <li>Since 1.12.0 the default was changed from false to true if there SloResponse notifications are configured.</li>
	 * </ul>
	 */
	@XmlAttribute(name="logoutNotifications", required = false)
	private Boolean logoutNotifications;

	@XmlElement(name = "SloResponse")
	@Builder.Default
	private List<SloResponse> sloResponse = new ArrayList<>();

	public boolean logoutNotificationsEnabled() {
		return Boolean.TRUE.equals(logoutNotifications) ||
				(logoutNotifications == null && hasSloNotifications());
	}

	private boolean hasSloNotifications() {
		return sloResponse != null && sloResponse.stream().anyMatch(response -> response.getMode().isNotification());
	}

	public boolean skipHrdWithSsoSession() { return Boolean.TRUE.equals(skipHrdWithSsoSession); }

}
