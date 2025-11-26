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

package swiss.trustbroker.saml.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.SubjectName;
import swiss.trustbroker.federation.xmlconfig.SubjectNameMappings;
import swiss.trustbroker.saml.dto.CpResponse;

class SubjectNameMapperTest {

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,from-idp,initial",
			"IDM,null,from-idp,initial",
			"null,http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress,from-config-0,cpAttributeValue",
			"IDM,http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress,from-config-0,idmAttributeValue",
			"IDM:query,http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress,from-config-0,idmAttributeValue",
			"null,source-without-value,from-idp,initial",
			"CP,http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress,from-config-0,cpAttributeValue",
			"CP:idp:cpIssuer1:01,http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress,from-config-0,cpAttributeValue",
			"CP:idp:cpIssuer1:02,http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress,from-idp,initial",
			"PROPS,http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress,from-config-0,propertyAttribute",
	}, nullValues = "null")
	void adjustSubjectNameId(String source, String claim, String format, String expectedNameId) {
		var expectedSubjectNameIdClaim = CoreAttributeName.EMAIL.getNamespaceUri();
		var cpIssuer = "idp:cpIssuer1:01";
		var subjectNameMappings =
				SubjectNameMappings.builder()
								   .preserve(true)
								   .subjects(List.of(
										   SubjectName.builder()
													  .source(source)
													  .claim(claim)
													  .format(format)
													  .build()))
								   .build();
		var relyingParty = RelyingParty.builder()
									   .id("rpIssuer1")
									   .subjectNameMappings(subjectNameMappings)
									   .build();
		var userDetails = Map.of(Definition.builder()
										   .name("anyAuditName")
										   .namespaceUri(expectedSubjectNameIdClaim)
										   .source("IDM:query")
										   .build(), List.of("idmAttributeValue"));
		var cpAttributes = Map.of(Definition.builder()
										   .name("anyAuditName")
										   .namespaceUri(expectedSubjectNameIdClaim)
										   .build(), List.of("cpAttributeValue"));
		var properties = Map.of(Definition.builder()
											.name("anyAuditName")
											.namespaceUri(expectedSubjectNameIdClaim)
											.build(), List.of("propertyAttribute"));
		// modified and logged
		var cpResponse0 = CpResponse.builder()
									.issuer(cpIssuer)
									.originalNameId("initial")
									.nameId("initial")
									.nameIdFormat("from-idp")
									.userDetails(userDetails)
									.attributes(cpAttributes)
									.properties(properties)
									.build();
		SubjectNameMapper.adjustSubjectNameId(cpResponse0, relyingParty);
		assertThat(cpResponse0.getNameId(), is(expectedNameId));
		assertThat(cpResponse0.getNameIdFormat(), is(format));
	}

	@Test
	void adjustSubjectNameIdMultipleMatch() {
		var expectedSubjectNameIdClaim = CoreAttributeName.EMAIL.getNamespaceUri();
		var cpIssuer = "cpIssuer1";
		var subjectNameMappings =
				SubjectNameMappings.builder()
								   .preserve(true)
								   .subjects(List.of(
										   SubjectName.builder()
													  .source("PROPS")
													  .claim(expectedSubjectNameIdClaim)
													  .format("from-config-prop")
													  .build(),
										   SubjectName.builder()
													  .source("IDM")
													  .claim(expectedSubjectNameIdClaim)
													  .format("from-config-idm")
													  .build()
								   			))
								   .build();
		var relyingParty = RelyingParty.builder()
									   .id("rpIssuer1")
									   .subjectNameMappings(subjectNameMappings)
									   .build();
		var userDetails = Map.of(Definition.builder()
										   .name("anyAuditName")
										   .namespaceUri(expectedSubjectNameIdClaim)
										   .source("IDMQuery")
										   .build(), List.of("idmAttributeValue"));
		var properties = Map.of(Definition.builder()
										  .name("anyAuditName")
										  .namespaceUri(expectedSubjectNameIdClaim)
										  .build(), List.of("propertyAttribute"));

		var cpResponse0 = CpResponse.builder()
									.issuer(cpIssuer)
									.originalNameId("initial")
									.nameId("initial")
									.nameIdFormat("from-idp")
									.userDetails(userDetails)
									.properties(properties)
									.build();
		SubjectNameMapper.adjustSubjectNameId(cpResponse0, relyingParty);
		assertThat(cpResponse0.getNameId(), is("propertyAttribute"));
		assertThat(cpResponse0.getNameIdFormat(), is("from-config-prop"));
	}

	@Test
	void getNameIdFromUserDetailsTest() {
		String namespaceUri = CoreAttributeName.EMAIL.getNamespaceUri();
		String idmAttributeValue = "idmAttributeValue";
		var userDetails = Map.of(Definition.builder()
										   .name("anyAuditName")
										   .namespaceUri(namespaceUri)
										   .source("IDMQuery")
										   .build(), List.of(idmAttributeValue));
		var cpResponse = CpResponse.builder()
									.originalNameId("initial")
									.nameId("initial")
									.nameIdFormat("from-idp")
									.userDetails(userDetails)
									.build();
		assertEquals(idmAttributeValue, SubjectNameMapper.getNameIdFromUserDetails(cpResponse, "IDM", namespaceUri));
		assertEquals(idmAttributeValue, SubjectNameMapper.getNameIdFromUserDetails(cpResponse, "IDMQuery", namespaceUri));
		assertNull(SubjectNameMapper.getNameIdFromUserDetails(cpResponse, "IDMQuery", "unknown"));
		assertEquals(idmAttributeValue, SubjectNameMapper.getNameIdFromUserDetails(cpResponse, null, namespaceUri));
		assertNull(SubjectNameMapper.getNameIdFromUserDetails(cpResponse, "PROPS", namespaceUri));

	}
}
