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

package swiss.trustbroker.saml.util;

import java.util.List;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.saml.saml2.core.StatusCode;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.common.config.RegexNameValue;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.config.dto.SamlNamespace;
import swiss.trustbroker.config.dto.SamlProperties;

/**
 * Performs mapping between Flow ID, SAML error codes, OIDC error codes, UI error codes.
 */
@Slf4j
public class SamlStatusCode {

	private SamlStatusCode() {
	}

	public static String toOidcErrorCode(OidcProperties oidcProperties, String statusCode, String nestedStatusCode,
			String statusMessage, String authServerErrorCode) {
		if (oidcProperties == null) {
			return null;
		}
		var result = mapByRegex(oidcProperties.getSamlErrorCodeRegexMappings(), statusCode, nestedStatusCode, statusMessage,
				authServerErrorCode);
		if (result == null) {
			result = mapByNamespace(oidcProperties.getSamlNamespacesMappedToOidcFormat(),
					statusCode, nestedStatusCode, statusMessage);
		}
		log.debug("Mapped SAML statusCode={} nestedStatusCode={} statusMessage={} authServerErrorCode={} to oidcErrorCode={}",
				statusCode, nestedStatusCode, statusMessage, authServerErrorCode, result);
		return result;
	}

	private static String mapByRegex(List<RegexNameValue> samlErrorCodeRegexMappings, String... errorCodes) {
		if (samlErrorCodeRegexMappings == null) {
			return null;
		}
		for (var mapping : samlErrorCodeRegexMappings) {
			var result = matchesRegex(mapping, errorCodes);
			if (result != null) {
				return result;
			}
		}
		return null;
	}

	private static String matchesRegex(RegexNameValue regexNameValue, String... statusValues) {
		if (regexNameValue == null || regexNameValue.getPattern() == null) {
			return null;
		}
		for (var statusValue : statusValues) {
			// SAML responder is ignored, does not make sense as OIDC error code
			if (statusValue == null || StatusCode.RESPONDER.equals(statusValue)) {
				continue;
			}
			var matcher = regexNameValue.getPattern().matcher(statusValue);
			if (matcher.matches()) {
				if (matcher.groupCount() > 0) {
					return toOidcCode(matcher.group(1), null);
				}
				return regexNameValue.getValue();
			}
		}
		return null;
	}

	private static String mapByNamespace(List<SamlNamespace> samlNamespacesMappedToOidcFormat, String statusCode,
			String nestedStatusCode, String statusMessage) {
		if (samlNamespacesMappedToOidcFormat == null) {
			return null;
		}
		for (var namespace : samlNamespacesMappedToOidcFormat) {
			// SAML responder is ignored, does not make sense as OIDC error code
			if (!StatusCode.RESPONDER.equals(statusCode) && hasNamespace(statusCode, namespace.getNamespace())) {
				return toOidcCode(statusCode, namespace.getPrefix());
			}
			if (hasNamespace(nestedStatusCode, namespace.getNamespace())) {
				return toOidcCode(nestedStatusCode, namespace.getPrefix());
			}
			if (hasNamespace(statusMessage, namespace.getNamespace())) {
				return toOidcCode(statusMessage, namespace.getPrefix());
			}
		}
		return null;
	}

	// extend id with namespace from FlowNamespaces that is matching prefix
	// if prefix is empty, the first one with no prefix is used or if none the first one with prefix
	public static String addNamespace(SamlProperties samlProperties, String id, String prefix) {
		// no config or ID already prefixed
		if (id == null || id.indexOf(':') >= 0 ||
				samlProperties == null || CollectionUtils.isEmpty(samlProperties.getFlowPolicyNamespaces())) {
			return id;
		}
		SamlNamespace defaultNamespace = null;
		for (var namespace : samlProperties.getFlowPolicyNamespaces()) {
			if (StringUtils.isEmpty(namespace.getPrefix())) {
				if (StringUtils.isEmpty(prefix)) {
					// both have no prefix
					return addNamespace(namespace, id);
				}
				if (defaultNamespace == null) {
					defaultNamespace = namespace;
				}
			}
			if (prefix != null && prefix.equals(namespace.getPrefix())) {
				// exact prefix match
				return addNamespace(namespace, id);
			}
		}
		if (defaultNamespace != null) {
			// default namespace defined
			return addNamespace(defaultNamespace, id);
		}
		// fallback to first namespace
		return addNamespace(samlProperties.getFlowPolicyNamespaces().get(0), id);
	}

	private static String addNamespace(SamlNamespace namespace, String id) {
		return namespace.getNamespace() + ':' + id;
	}

	static boolean hasNamespace(String value, String namespace) {
		return value != null && namespace != null && value.startsWith(namespace);
	}

	static String removeNamespace(String code) {
		if (code == null) {
			return null;
		}
		var separatorIndex = code.lastIndexOf(':');
		if (separatorIndex < 0) {
			return code;
		}
		return code.substring(separatorIndex + 1);
	}

	static String toSnakeCase(String code) {
		if (code == null) {
			return null;
		}
		var result = new StringBuilder();
		var afterLowerCase = false;
		var consecutiveUpperCase = false;
		for (int ii = 0; ii < code.length(); ++ii) {
			var ch = code.charAt(ii);
			if (Character.isUpperCase(ch)) {
				if (afterLowerCase) {
					result.append('_');
				}
				consecutiveUpperCase = ii > 0 && !afterLowerCase;
				afterLowerCase = false;
				result.append(Character.toLowerCase(ch));
			}
			else {
				if (consecutiveUpperCase) {
					result.insert(result.length() - 1, '_');
				}
				consecutiveUpperCase = false;
				afterLowerCase = true;
				result.append(ch);
			}
		}
		return result.toString();
	}

	static String toOidcCode(String code, String prefix) {
		var result = toSnakeCase(removeNamespace(code));
		if (StringUtils.isNotEmpty(prefix)) {
			result = prefix + '_' + result;
		}
		return result;
	}

	public static String toUiErrorCode(String code) {
		if (code == null) {
			return null;
		}
		return removeNamespace(code).toLowerCase();
	}


}
