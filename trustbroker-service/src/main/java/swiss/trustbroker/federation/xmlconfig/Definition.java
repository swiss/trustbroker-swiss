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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.common.saml.util.AttributeRegistry;

/**
 * Attribute definition.
 *
 * For custom attributes see AttributeInitializer.
 *
 * @see swiss.trustbroker.api.sessioncache.service.AttributeInitializer
 */
@XmlRootElement(name = "Definition")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@EqualsAndHashCode(of = { "name", "namespaceUri", "source" }) // oidcName is derived only and does not need to be in key
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
@Slf4j
public class Definition implements Serializable, AttributeName {

	static final String LIST_ATTRIBUTE_DELIMITER = ",";

	/**
	 * Short name used in auditing and for IDM attribute addressing.
	 * Compound primary key member in attribute maps using Definition(De)Serializer.
	 */
	@XmlAttribute(name = "name")
	private String name;

	/**
	 * The long name is used in the generated SAML assertion towards the RP.
	 * Compound primary key member in attribute maps using Definition(De)Serializer.
	 */
	@XmlAttribute(name = "namespaceUri")
	private String namespaceUri;

	/**
	 * Source of the definition
	 * Compound primary key member in attribute maps using Definition(De)Serializer.
	 */
	@XmlAttribute(name = "source")
	private String source;

	/**
	 * Known external attributes we just document here - used when we cannot use namespaceUri due to semantics.
	 */
	@XmlAttribute(name = "altName")
	private String altName;

	/**
	 * The claim names used when emitting an attribute to an OIDC client (comma-separated -
	 * as an attribute, it cannot be a List).
	 *
	 * @see Definition#oidcNamesToList(String)
	 * @see Definition#oidcNameListToString(List)
 	 */
	@XmlAttribute(name = "oidcNames")
	private String oidcNames;

	/**
	 * Indicates whether this field is considered CID (client identifying data).
	 * <br/>
	 * Default: null - global default is used
	 *
	 * @since 1.8.0
	 */
	@XmlAttribute(name = "cid")
	private Boolean cid;

	/**
	 * Multi value handling.
	 * <br/>
	 * Default: ORIGINAL
	 */
	@XmlAttribute(name = "multiValued")
	@Builder.Default
	private Multivalued multiValued = Multivalued.ORIGINAL;

	/**
	 * Comma-separated list of mappers to be used for the value.
	 *
	 * @since 1.9.0
	 */
	@XmlAttribute(name = "mappers")
	private String mappers;

	/**
	 * Mapper to be used for the value.
	 *
	 * @deprecated use mappers
	 */
	@Deprecated(since = "1.9.0", forRemoval = true)
	@XmlAttribute(name = "oidcMapper")
	private ClaimsMapper oidcMapper;

	/**
	 * Provision this attribute to IDM.
	 * <br/>
	 * The value or list of comma-separated values indicate into what type(s) of IDM object provisioning services should
	 * provision this data.
	 * <br/>
	 * The actual fields to provision would usually be selected based on name/namespace URI.
	 * <br/>
	 * Generic values: true (a provisioning service selects an appropriate target), false (not provisioned - single value only).
	 * <br/>
	 * Default: false
	 *
	 * @since 1.9.0
	 * @see swiss.trustbroker.api.idm.service.IdmProvisioningService
	 */
	@XmlAttribute(name = "provision")
	private String provision;

	/**
	 * ID attribute for provisioning.
	 *
	 * @since 1.9.0
	 * @see swiss.trustbroker.api.idm.service.IdmProvisioningService
	 */
	@XmlAttribute(name = "provisioningId")
	private Boolean provisioningId;


	/**
	 * Single value from constant configuration (we currently only use single valued in XML via ConstAttributes).
 	 */
	@XmlAttribute(name = "value")
	private String value;

	/**
	 * To restrict emitting an attribute, the scope can be set as follows:
	 * <ul>
	 *     <li>saml: Use only in SAML assertions</li>
	 *     <li>oidc: Use only in OIDC tokens (oidcName must be set)</li>
	 * </ul>
	 * If not set, the attribute is emitted on all protocols and any requested OIDC scope.
 	 */
	@XmlAttribute(name = "scope")
	private String scope;

	public Definition(String name) {
		this.name = name;
	}

	public Definition(String name, String namespaceUri) {
		this.name = name;
		this.namespaceUri = namespaceUri;
	}

	public Definition(AttributeName attributeName) {
		this.name = attributeName.getName();
		this.namespaceUri = attributeName.getNamespaceUri();
		this.altName = attributeName.getAltName();
		this.cid = attributeName.getCid();
		this.source = attributeName.getSource();
		if (attributeName instanceof Definition definition) {
			this.oidcNames = definition.oidcNames;
			this.mappers = definition.mappers;
		}
		else {
			this.oidcNames = oidcNameListToString(attributeName.getOidcNameList());
			this.mappers = null;
		}
	}

	public Definition(String name, String namespaceUri, String singleValue) {
		this.name = name;
		this.namespaceUri = namespaceUri;
		this.value = singleValue;
	}

	public static Definition ofName(String name) {
		return Definition.builder().name(name).build();
	}

	public static Definition ofName(AttributeName name) {
		return Definition.builder().name(name.getName()).build();
	}

	public static Definition ofNameAndSource(String name, String source) {
		return Definition.builder().name(name).source(source).build();
	}

	public static Definition ofNameAndSource(AttributeName name, String source) {
		return Definition.builder().name(name.getName()).source(source).build();
	}

	public static Definition ofNames(String name, String namespaceUri) {
		return Definition.builder().name(name).namespaceUri(namespaceUri).build();
	}

	public static Definition ofNames(AttributeName name) {
		return Definition.builder().name(name.getName()).namespaceUri(name.getNamespaceUri()).build();
	}

	public static Definition ofNamesAndSource(String name, String namespaceUri, String source) {
		return Definition.builder().name(name).namespaceUri(namespaceUri).source(source).build();
	}

	public static Definition ofNamesAndSource(AttributeName name, String source) {
		return Definition.builder().name(name.getName()).namespaceUri(name.getNamespaceUri()).source(source).build();
	}

	private static String oidcNameListToString(List<String> oidcNameList) {
		return CollectionUtils.isEmpty(oidcNameList) ? null : oidcNameList.stream().collect(Collectors.joining(", "));
	}

	private static List<String> oidcNamesToList(String oidcNames) {
		return oidcNames != null ? Arrays.asList(oidcNames.split(LIST_ATTRIBUTE_DELIMITER)) : Collections.emptyList();
	}

	@Override
	@JsonIgnore
	public List<String> getOidcNameList() {
		return oidcNamesToList(oidcNames);
	}

	@JsonIgnore
	@SuppressWarnings("java:S5738") // contains fallback to deprecated oidcMapper
	public List<ClaimsMapper> getClaimsMappers() {
		if (oidcMapper != null) {
			log.warn("Deprecated attribute oidcMapper={} used on name={} namespaceUri={} - change to mappers={}",
					oidcMapper, name, namespaceUri, oidcMapper);
		}
		if (StringUtils.isEmpty(mappers)) {
			// fallback: transition
			return oidcMapper != null ? Collections.singletonList(oidcMapper) : Collections.emptyList();
		}
		return Arrays.stream(mappers.split(LIST_ATTRIBUTE_DELIMITER))
				.map(ClaimsMapper::of)
				.filter(Objects::nonNull)
				.toList();
	}

	@JsonIgnore
	public List<String> getMultiValues() {
		if (value != null) {
			return List.of(value); // from config
		}
		return Collections.emptyList();
	}

	public AttributeName findAttributeName() {
		AttributeName attributeName = null;
		if (namespaceUri != null) {
			attributeName = AttributeRegistry.forName(namespaceUri);
		}
		if (attributeName == null && name != null) {
			attributeName = AttributeRegistry.forName(name);
		}
		return attributeName;
	}

	// true for all matching combinations of name and namespaceUri, false for nulls
	// (temporary Definition objects may have only a name containing a name or namespaceUri)
	@Override
	public boolean equalsByNameOrNamespace(AttributeName attributeName, String source) {
		if (attributeName == null) {
			return false;
		}
		var ret = false;
		if (name != null && namespaceUri != null) {
			ret = name.equals(attributeName.getName()) || name.equals(attributeName.getNamespaceUri()) ||
					namespaceUri.equals(attributeName.getNamespaceUri()) || namespaceUri.equals(attributeName.getName());
		}
		else if (namespaceUri != null) {
			ret = namespaceUri.equals(attributeName.getName()) || namespaceUri.equals(attributeName.getNamespaceUri());
		}
		else if (name != null) {
			ret = name.equals(attributeName.getName()) || name.equals(attributeName.getNamespaceUri());
		}
		return ret && isEqualsBySource(source);
	}

	@JsonIgnore
	public boolean isProvisioningAttribute() {
		return provision != null && !provision.equalsIgnoreCase(Boolean.FALSE.toString());
	}

	@JsonIgnore
	public boolean isProvisioningIdAttribute() {
		return Boolean.TRUE.equals(provisioningId);
	}

}
