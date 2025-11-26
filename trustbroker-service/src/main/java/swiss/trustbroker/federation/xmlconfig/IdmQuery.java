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
import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import swiss.trustbroker.api.idm.dto.IdmRequest;
import swiss.trustbroker.api.idm.service.IdmQueryService;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;

/**
 * Configures an IDM query to be executed.
 *
 * @see IdmQueryService
 */
@XmlRootElement(name = "IDMQuery")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IdmQuery implements Serializable, IdmRequest {

	/**
	 * 	A query needs an ID when its name is not unique and its execution needs to be controlled via a custom script based
	 * 	on CP input usually.
 	 */
	@XmlAttribute(name = "id")
	private String id;

	/**
	 * Name of the query, depending on the IdmService implementation.
	 */
	@XmlAttribute(name = "name")
	private String name;

	/**
	 * Used to select an IdmService implementation
	 * @since 1.10.0
	 */
	@XmlAttribute(name = "store")
	private String store;

	/**
	 * SAML federation filter to be applied to the user query.
	 */
	@XmlAttribute(name = "issuerNameId")
	private String issuerNameId;

	/**
	 * Instead of an issuerNameId the SAML federation can also be identified via its fully qualified homeName attribute as an
	 * input.
	 */
	@XmlAttribute(name = "issuerNameIdNS")
	private String issuerNameIdNS;

	/**
	 * Handling of the user status in IDM.
	 */
	@XmlAttribute(name = "statusPolicy")
	private StatusPolicy statusPolicy;

	/**
	 * Client External ID (tenant) as filtering parameter for the IDM.
	 */
	@XmlElement(name = "ClientExtId")
	private String clientExtId;

	/**
	 * Subject Name ID as filtering parameter for the IDM.
	 */
	@XmlElement(name = "SubjectNameId")
	private String subjectNameId;

	/**
	 * Application as filtering parameter for the IDM.
	 */
	@XmlElement(name = "AppFilter")
	private String appFilter;

	/**
	 * User details selection identifies the IDM attributes passed through to the RP side.
	 */
	@XmlElement(name = "UserDetailsSelection")
	private AttributesSelection userDetailsSelection;

	public StatusPolicy statusPolicyWithDefault() {
		return statusPolicy != null ? statusPolicy : StatusPolicy.FETCH_ACTIVE_ONLY;
	}

	@JsonIgnore
	@Override
	public boolean isFetchActiveOnly() {
		return statusPolicyWithDefault() == StatusPolicy.FETCH_ACTIVE_ONLY;
	}

	@JsonIgnore
	@Override
	public List<AttributeName> getAttributeSelection() {
		return userDetailsSelection != null && userDetailsSelection.getDefinitions() != null ?
				Collections.unmodifiableList(userDetailsSelection.getDefinitions()) :
				Collections.emptyList();
	}

	@JsonIgnore
	@Override
	public String getUserStatusPolicy() {
		return statusPolicyWithDefault().name();
	}

	@JsonIgnore
	@Override
	public AttributeName getIssuerNameIdAttribute() {
		return new Definition(issuerNameId, issuerNameIdNS);
	}

	@JsonIgnore
	@Override
	public AttributeName getSubjectNameIdAttribute() {
		return new Definition(subjectNameId);
	}

	public static IdmQuery of(IdmRequest idmRequest) {
		if (idmRequest instanceof IdmQuery idmQuery) {
			return idmQuery;
		}
		else {
			return ofRequest(idmRequest);
		}
	}

	// deep copy

	private static IdmQuery ofRequest(IdmRequest idmRequest) {
		var issuerNameIdAttribute = idmRequest.getIssuerNameIdAttribute();
		var subjectNameIdAttribute = idmRequest.getSubjectNameIdAttribute();
		var result =  IdmQuery.builder()
				.id(idmRequest.getId())
				.name(idmRequest.getName())
				.issuerNameId(issuerNameIdAttribute != null ? issuerNameIdAttribute.getName() : null)
				.issuerNameIdNS(issuerNameIdAttribute != null ? issuerNameIdAttribute.getNamespaceUri() : null)
				.subjectNameId(subjectNameIdAttribute != null ? subjectNameIdAttribute.getName() : null)
				.clientExtId(idmRequest.getClientExtId())
				.appFilter(idmRequest.getAppFilter())
				.statusPolicy(StatusPolicy.of(idmRequest.getUserStatusPolicy()))
				.build();
		copyUserDetailsSelection(idmRequest.getAttributeSelection(), result);
		return result;
	}

	private static void copyUserDetailsSelection(List<AttributeName> attributeNames, IdmQuery result) {
		if (attributeNames != null) {
			var userDetailsSelection = new AttributesSelection();
			userDetailsSelection.setDefinitions(new ArrayList<>());
			for (var attributeName : attributeNames) {
				userDetailsSelection.getDefinitions().add(new Definition(attributeName));
			}
			result.setUserDetailsSelection(userDetailsSelection);
		}
	}
}
