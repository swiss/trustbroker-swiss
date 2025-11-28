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

package swiss.trustbroker.common.saml.util;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.common.exception.TechnicalException;

/**
 * Registry for attribute names populated through AttributeInitializer implementations and from configuration.
 *
 * @see swiss.trustbroker.api.sessioncache.service.AttributeInitializer
 */
@Slf4j
public class AttributeRegistry {

	private static final Map<String, AttributeName> ATTRIBUTE_NAME_MAP = new ConcurrentHashMap<>();

	private AttributeRegistry() {}

	public static AttributeName forName(String name) {
		if (ATTRIBUTE_NAME_MAP.isEmpty()) {
			throw new TechnicalException("AttributeRegistry used before initialization");
		}
		return ATTRIBUTE_NAME_MAP.get(name);
	}

	/**
	 * Stores the values of the attribute in the registry along with the attribute. If a value already exists, it is not
	 * overwritten, but the instance's values may be updated.
	 *
	 * @param attribute if 'name' is present already in the registry, and the present value is a MutableAttributeName,
	 *                  the other fields of the input are updated from this parameter's values
	 */
	public static void updateAttributeNameFromConfig(AttributeName attribute) {
		putOrUpdateAttributeName(attribute, true);
	}

	/**
 	 * Stores the values of the attribute in the registry along with the attribute. If a value already exists, it is not
	 * overwritten or updated. This method is to be used by normal AttributeInitializer should use.
	 *
	 * @param attribute stored in the registry unless the names are already present
	 *
	 */
	public static void putAttributeName(AttributeName attribute) {
		putOrUpdateAttributeName(attribute, false);
	}

	private static void putOrUpdateAttributeName(AttributeName attribute, boolean updateExisting) {
		var previous = putName(attribute.getName(), "Name", attribute);
		// name is the key that has to be unique - only update matches based on this
		if (updateExisting && previous != null && previous instanceof MutableAttributeName mutable) {
			updateMutableAttribute(mutable, attribute);
			attribute = mutable; // use updated instance for other names
		}
		putName(attribute.getNamespaceUri(), "FullyQualifiedName", attribute);
		putName(attribute.getAltName(), "AltName", attribute);
		var oidcNameList = attribute.getOidcNameList();
		if (oidcNameList != null) {
			for (var oidcName : oidcNameList) {
				putName(oidcName, "OidcName", attribute);
			}
		}
	}

	private static void updateMutableAttribute(MutableAttributeName mutable, AttributeName attribute) {
		log.info("Updating fields of name={} current={} to modified={}", mutable.getName(), mutable, attribute);
		if (attribute.getNamespaceUri() != null) {
			log.debug("Changing {}.{} currentAamespaceUri={} to modifiedNamespaceUri={}",
					mutable.getClass().getSimpleName(), mutable.getName(), mutable.getNamespaceUri(), attribute.getNamespaceUri());
			mutable.setNamespaceUri(attribute.getNamespaceUri());
		}
		if (attribute.getAltName() != null) {
			log.debug("Changing {}.{} currentAltName={} to modifiedAltName={}",
					mutable.getClass().getSimpleName(), mutable.getName(), mutable.getAltName(), attribute.getAltName());
			mutable.setAltName(attribute.getAltName());
		}
		if (attribute.getOidcNameList() != null) {
			log.debug("Changing {}.{} currentOidcNameList={} to modifiedOidcNameList={}",
					mutable.getClass().getSimpleName(), mutable.getName(), mutable.getOidcNameList(), attribute.getOidcNameList());
			mutable.setOidcNameList(attribute.getOidcNameList());
		}
	}

	private static AttributeName putName(String name, String description, AttributeName attributeName) {
		if (name != null) {
			var previous = ATTRIBUTE_NAME_MAP.putIfAbsent(name, attributeName);
			if (previous != null) {
				handleDuplicate(name, description, attributeName, previous);
			}
			else {
				log.debug("{}={} set to value={}", description, name, attributeName);
			}
			return previous;
		}
		return null;
	}

	private static void handleDuplicate(String name, String description, AttributeName attributeName, AttributeName previous) {
		// special case: core attributes must win (this happens if the FQDN etc. is set via config for core attributes):
		if (attributeName instanceof CoreAttributeName && !(previous instanceof CoreAttributeName)) {
			ATTRIBUTE_NAME_MAP.put(name, attributeName);
			log.debug("{}={} is used more than once - overwriting previous={} with core value={}", description, name,
					previous, attributeName);
		}
		else {
			log.debug("{}={} is used more than once - not overwriting with value={}", description, name, attributeName);
		}
	}

	// for tests:
	static void clear() {
		log.info("Clearing AttributeRegistry");
		ATTRIBUTE_NAME_MAP.clear();
	}
}
