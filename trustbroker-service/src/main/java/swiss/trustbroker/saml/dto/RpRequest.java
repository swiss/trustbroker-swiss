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

package swiss.trustbroker.saml.dto;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.federation.xmlconfig.ClaimsProvider;
import swiss.trustbroker.federation.xmlconfig.QoaComparison;

/**
 * Class is used to implement the contract towards ScriptService on RP request processing side.
 * See CpResponse class for counterpart on CP side.
 */
@Data
@EqualsAndHashCode(callSuper=false)
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@SuppressWarnings("java:S2250") // all the lists in here are small
@Slf4j
public class RpRequest extends ResponseStatus {

	/**
	 * Context key set by script to add one or several query parameters to the authorization request towards an OIDC CP.
	 * @since 1.11.0
	 */
	public static final String CONTEXT_OIDC_AUTHORIZATION_QUERY_PARAMETER = "xtb.oidc.CP.authorization.queryParameter";

	/**
	 * Referer header from the incoming HTTP request.
	 */
	private String referer;

	/**
	 * Issuer of the incoming SAML request
	 */
	private String rpIssuer;

	/**
	 * ID of the incoming message (e.g. AuthnRequest).
	 */
	private String requestId;

	/**
	 * Application name e.g. from AuthnRequest.ProviderName.
	 */
	private String applicationName;

	/**
	 * AuthnRequest RequestedAuthnContext.ContextClassRefs.
	 */
	@Builder.Default
	private List<String> contextClasses = new ArrayList<>();

	/**
	 * Map to store internal processing attributes required during federation.
	 */
	@Builder.Default
	private Map<String, String> context = new HashMap<>();

	/**
	 * AuthnRequest RequestedAuthnContext.comparisonType.
	 *
	 * @since 1.9.0
	 */
	private QoaComparison comparisonType;

	/**
	 * Allow to use a non-angular version of the HRD screen
	 * <br/>
	 * Default: false
	 */
 	@Builder.Default
	private boolean useSkinnyHrdScreen = false;

	/**
	 * ClaimsProvider mappings for RelyingParty.
	 */
	@Builder.Default
	private List<ClaimsProvider> claimsProviders = new ArrayList<>();

	/**
	 * UI objects for the HRD screen.
	 */
	@Builder.Default
	private UiObjects uiObjects = new UiObjects();

	/**
	 * @param id
	 * @return ClaimsProvider with that ID or null
	 */
	public ClaimsProvider getClaimsProvider(String id) {
		return claimsProviders.stream().filter(cp -> cp.getId().equals(id)).findFirst().orElse(null);
	}

	/**
	 * @return HRD: Federation to single CP possible
	 */
	public boolean hasSingleClaimsProvider() {
		return 	claimsProviders.size() == 1; // uiObjects might still be empty because rendering phase was skipped
	}

	/**
	 * @return Number of ClaimsProviders in the mapping.
	 */
	public int getClaimsProvidersCount() {
		return claimsProviders.size();
	}

	/**
	 * @param uiObject HRD: Manually construct a HRD tile - script hook
	 */
	public void addUiElement(UiObject uiObject) {
		uiObjects.addTile(uiObject);
	}

	/**
	 * @param uiBanner HRD: Manually construct a HRD banner - script hook
	 */
	public void addBanner(UiBanner uiBanner) {
		uiObjects.addBanner(uiBanner);
	}

	/**
	 * @param id HRD: Remove a specific ClaimsProvider
	 * @return removed ClaimsProvider
	 */
	public ClaimsProvider dropClaimsProvider(String id) {
		var ret = getClaimsProvider(id);
		if (ret != null) {
			claimsProviders.remove(ret);
		}
		return ret;
	}

	/**
	 * @param id HRD: Retain a specific one if present, to automatically dispatch
	 * @return retained ClaimsProvider
	 */
	public ClaimsProvider retainClaimsProvider(String id) {
		var ret = getClaimsProvider(id);
		if (ret != null) {
			claimsProviders.retainAll(List.of(ret));
		}
		return ret;
	}

	/**
	 * @param contextClass
	 * @return If context class was set in request.
	 */
	public boolean hasContextClass(String contextClass) {
		return contextClasses.contains(contextClass);
	}

	/**
	 * @param contextClass Add context class if not yet present.
	 * @return true if added
	 */
	public boolean addContextClass(String contextClass) {
		if (!hasContextClass(contextClass)) {
			contextClasses.add(contextClass);
			return true;
		}
		return false;
	}

	/**
	 * @param contextClass Remove context class.
	 * @return true if removed
	 */
	public boolean removeContextClass(String contextClass) {
		return contextClasses.remove(contextClass);
	}

	/**
	 * @param contextClass Retain a single context class if present.
	 * @return true if modified
	 * @since 1.9.0
	 */
	public boolean retainContextClass(String contextClass) {
		if (contextClasses.contains(contextClass)) {
			return contextClasses.retainAll(List.of(contextClass));
		}
		return false;
	}

	/**
	 * Add internal federation context required during federation.
	 * @return replaced context value or null
	 */
	public String addContext(String name, String value) {
		return context.put(name, value);
	}

	/**
	 * Query internal federation context setup during federation.
	 * @return context value or null if not found.
	 */
	public String getContext(String name) {
		return context.get(name);
	}

	/**
	 * Remove internal federation context required during federation.
	 * @return removed context value or null.
	 */
	public String removeContext(String name) {
		return context.remove(name);
	}

}
