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
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Configuration for an individual error code.
 */
@XmlRootElement(name = "FlowPolicy")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Slf4j
public class Flow implements Serializable {

	public static final String CONTINUE_FLAG = "continue";

	public static final String RELOGIN_FLAG = "relogin";

	public static final String LINK_FLAG = "link";

	public static final String SUPPORT_FLAG = "support";

	/**
	 * 	SAML error code with or without namespace, adding <pre>trustbroker.config.saml.flowNamespaces</pre> if needed.
	 * 	<br/>
	 * 	E.g. UserCancel, PwResetSuccessful, PwResetFailed, PwResetTmpBlocked, urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal
 	 */
	@XmlAttribute
	private String id;

	/**
	 * Prefix if there are multiple <pre>trustbroker.config.saml.flowNamespaces</pre>.
 	 */
	@XmlAttribute
	private String namespacePrefix;

	/**
	 * Show error page including a support info section.
	 */
	@XmlAttribute
	@Builder.Default
	private Boolean supportInfo = Boolean.FALSE;

	/**
	 * Show error page including re-login button (triggers another login).
	 */
	@XmlAttribute
	@Builder.Default
	private Boolean reLogin = Boolean.FALSE;

	/**
	 * Show error page including continue to application button (send SAML error on to application).
	 */
	@XmlAttribute
	@Builder.Default
	private Boolean appContinue = Boolean.FALSE;

	/**
	 * Show error page including a link to <code>appUrl</code>.
	 *
	 * @since 1.10.0
	 */
	@XmlAttribute
	@Builder.Default
	private Boolean link = Boolean.FALSE;

	/**
	 * Redirect to (application-specific) URL instead of showing an error page.
	 *
	 * @since 1.8.0
	 */
	@XmlAttribute
	private String appRedirectUrl;

	/**
	 * Show a link to further information on the error page (general error information on the application or specific to this
	 * error code).
	 */
	@XmlAttribute
	private String appUrl;

	/**
	 * Show (application specific) support e-mail address on the error page.
	 */
	@XmlAttribute
	private String supportEmail;

	/**
	 * Show (application specific) support phone number on the error page.
	 */
	@XmlAttribute
	private String supportPhone;

	public boolean showErrorPage() {
		return doShowSupportInfo() || doReLogin() || doAppContinue() || doAppRedirect() || doLink();
	}

	public boolean doAppRedirect() { return appRedirectUrl != null; }

	public List<String> uiFlags() {
		List<String> flags = new ArrayList<>();
		if (doShowSupportInfo()) {
			flags.add(SUPPORT_FLAG);
		}
		if (doReLogin()) {
			flags.add(RELOGIN_FLAG);
		}
		if (doAppContinue()) {
			flags.add(CONTINUE_FLAG);
		}
		if (doLink()) {
			flags.add(LINK_FLAG);
		}
		return flags;
	}

	private boolean doShowSupportInfo() {
		return Boolean.TRUE.equals(supportInfo);
	}

	private boolean doReLogin() {
		return Boolean.TRUE.equals(reLogin);
	}

	private boolean doAppContinue() {
		return Boolean.TRUE.equals(appContinue);
	}

	private boolean doLink() {
		return Boolean.TRUE.equals(link);
	}
}
