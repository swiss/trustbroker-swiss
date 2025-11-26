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

package swiss.trustbroker.api.sessioncache.dto;

import java.util.List;
import java.util.Objects;

/**
 * Addressing of an attribute via name and/or namespace URI.
 */
public interface AttributeName {

	/**
	 * @return Audit and IDM relevant name, unique
	 */
	public String getName();

	/**
	 * @return Known external CP attributes we just document here - used when we cannot use namespaceUri due to semantics
	 * (can be null)
	 */
	public String getAltName();

	/**
	 * @return SAML attribute, value must be unique to prevent auditing to not display wrong short names
	 */
	public String getNamespaceUri();

	/**
	 * @return OIDC standard claim, served when standard claim mapping is enabled and no configured attribute has it in oidcNames
	 */
	public List<String> getOidcNameList();

	/**
	 * @return true if this field is considered CID (client identifying data) - default is null (use global defaults)
	 * @since 1.8.0
	 */
	@SuppressWarnings("java:S2447") // ternary with null
	default Boolean getCid() {
		return null;
	}

	/**
	 * @return source of the attribute
	 * @since 1.8.0
	 */
	@SuppressWarnings("java:S2447") // ternary with null
	default String getSource() {
		return null;
	}

	/**
	 * @return provisioning configuration of this attribute.
	 * @since 1.9.0
	 */
	default String getProvision() {
		return null;
	}

	// default name comparison:

	/**
	 * @param name
	 * @return true if name is not null and equals this by name
	 */
	default boolean equalsByName(String name) {
		return name != null && name.equals(getName());
	}

	/**
	 * @param namespace
	 * @return true if namespace is not null and equals this by namespace
	 */
	default boolean equalsByNamespace(String namespace) {
		return namespace != null && namespace.equals(getNamespaceUri());
	}

	/**
	 * @param attributeName
	 * @return true if attributeName is not null and equals this by name (ignoring the namespace)
	 * @see AttributeName#equalsByName(String)
	 */
	default boolean equalsByName(AttributeName attributeName) {
		return attributeName != null && equalsByName(attributeName.getName());
	}

	/**
	 * @param attributeName
	 * @return true if attributeName is not null and equals this by namespace (ignoring the name)
	 * @see AttributeName#equalsByNamespace(String)
	 * @since 1.8.0
	 */
	default boolean equalsByNamespace(AttributeName attributeName) {
		return attributeName != null && equalsByNamespace(attributeName.getNamespaceUri());
	}

	/**
	 * @param name
	 * @return true if name is not null and equals this by name <strong>or</strong> namespace
	 * @see AttributeName#equalsByName(String)
	 * @see AttributeName#equalsByNamespace(String)
	 */
	default boolean equalsByNameOrNamespace(String name) {
		return equalsByNameOrNamespace(name, null);
	}

	/**
	 * @param name
	 * @param source
	 * @return true if name is not null and equals this by name <strong>or</strong> namespace and source is null or matches,
	 * @see AttributeName#equalsByName(String)
	 * @see AttributeName#equalsByNamespace(String)
	 */
	default boolean equalsByNameOrNamespace(String name, String source) {
		return (equalsByName(name) || equalsByNamespace(name)) && isEqualsBySource(source);
	}

	/**
	 * @param attributeName
	 * @return true if attributeName is not null and equals this by name <strong>or</strong> namespace
	 * (the matching names/namespaces must not be null)
	 * @see AttributeName#equalsByName(String)
	 * @see AttributeName#equalsByNamespace(String)
	 */
	default boolean equalsByNameOrNamespace(AttributeName attributeName) {
		return equalsByNameOrNamespace(attributeName, null);
	}

	/**
	 * @param attributeName
	 * @param source
	 * @return true if attributeName is not null and equals this by name <strong>or</strong> namespace
	 * (the matching names/namespaces must not be null)
	 * @see AttributeName#equalsByName(String)
	 * @see AttributeName#equalsByNamespace(String)
	 */
	default boolean equalsByNameOrNamespace(AttributeName attributeName, String source) {
		if (attributeName == null) {
			return false;
		}
		boolean equalsBySource = isEqualsBySource(source);
		return (equalsByName(attributeName.getName()) || equalsByNamespace(attributeName.getNamespaceUri())) && equalsBySource;
	}

	/**
	 * @param source
	 * @return true if the sources are equals or null
	 */
	default boolean isEqualsBySource(String source) {
		if (source == null || getSource() == null) {
			return true;
		}
		return getSource().startsWith(source);
	}

	/**
	 * @param attributeName
	 * @return true if attributeName is not null and equals this by name <strong>and</strong> namespace
	 * (the matching names/namespaces may be null)
	 */
	default boolean equalsByNameAndNamespace(AttributeName attributeName) {
		return attributeName != null &&
				Objects.equals(getName(), attributeName.getName()) &&
				Objects.equals(getNamespaceUri(), attributeName.getNamespaceUri());
	}

}
