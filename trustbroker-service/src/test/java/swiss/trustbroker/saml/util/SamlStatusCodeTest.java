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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.opensaml.saml.saml2.core.StatusCode;
import swiss.trustbroker.common.config.RegexNameValue;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.config.dto.SamlNamespace;
import swiss.trustbroker.config.dto.SamlProperties;

class SamlStatusCodeTest {

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,null",
			StatusCode.UNKNOWN_PRINCIPAL + ",null,unknown_principal",
			StatusCode.UNKNOWN_PRINCIPAL + ",saml,saml_unknown_principal",
			"PwResetFailed,xtb,xtb_pw_reset_failed",
			"PwResetFailed,,pw_reset_failed",
			"PwResetFailed,null,pw_reset_failed"
	}, nullValues = "null")
	void toOidcCode(String code, String prefix, String expected) {
		assertThat(SamlStatusCode.toOidcCode(code, prefix), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null",
			StatusCode.UNKNOWN_PRINCIPAL + ",unknownprincipal",
			"PwResetFailed,pwresetfailed"
	}, nullValues = "null")
	void toUiErrorCode(String code, String expected) {
		assertThat(SamlStatusCode.toUiErrorCode(code), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,false",
			"null,any,false",
			StatusCode.UNKNOWN_PRINCIPAL + ",null,false",
			"PwResetFailed,null,false",
			"PwResetFailed,urn:oasis:names:tc:SAML:2.0:status,false",
			StatusCode.UNKNOWN_PRINCIPAL + ",urn:oasis:names:tc:SAML:2.0:status,true",
			StatusCode.UNKNOWN_PRINCIPAL + ",urn:example:names:tc:SAML:2.0:status,false"
	}, nullValues = "null")
	void removeNamespace(String code, String namespace, boolean expected) {
		assertThat(SamlStatusCode.hasNamespace(code, namespace), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null",
			StatusCode.UNKNOWN_PRINCIPAL + ",UnknownPrincipal",
			"PwResetFailed,PwResetFailed"
	}, nullValues = "null")
	void removeNamespace(String code, String expected) {
		assertThat(SamlStatusCode.removeNamespace(code), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null",
			"SNAKE,snake",
			"case,case",
			"camelCase,camel_case",
			"CAMELCase,camel_case",
			"camelCASE,camel_case",
			"PwResetFailed,pw_reset_failed",
			"NoAvailableIDP,no_available_idp",
			"InvalidNameIDPolicy,invalid_name_id_policy"
	}, nullValues = "null")
	void toSnakeCase(String code, String expected) {
		assertThat(SamlStatusCode.toSnakeCase(code), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,null,null,null",
			StatusCode.RESPONDER + ',' + StatusCode.UNKNOWN_PRINCIPAL + ",Unknown principal,invalid_status,unknown_principal",
			StatusCode.RESPONDER + ",PrincipalUnknown," + StatusCode.UNKNOWN_PRINCIPAL + ",invalid_status,unknown_principal",
			StatusCode.UNKNOWN_PRINCIPAL + ",PrincipalUnknown,Unknown principal,invalid_status,unknown_principal",
			StatusCode.RESPONDER + ',' + StatusCode.UNKNOWN_PRINCIPAL + ",Unknown principal,invalid_status,unknown_principal"
	}, nullValues = "null")
	void mapSamlStatusToOidcByNamespaces(String statusCode, String nestedStatusCode, String message, String authServerErrorCode,
			String expected) {
		var properties = new OidcProperties();
		properties.setSamlNamespacesMappedToOidcFormat(givenNamespaces());
		assertThat(SamlStatusCode.toOidcErrorCode(properties, statusCode, nestedStatusCode, message, authServerErrorCode),
				is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,null,null,null",
			// full match:
			StatusCode.RESPONDER + ',' + StatusCode.UNKNOWN_PRINCIPAL + ",Unknown principal,invalid_status,unauthorized_client",
			StatusCode.RESPONDER + ",PrincipalUnknown," + StatusCode.UNKNOWN_PRINCIPAL + ",invalid_status,unauthorized_client",
			StatusCode.UNKNOWN_PRINCIPAL + ",PrincipalUnknown,Unknown principal,invalid_status,unauthorized_client",
			// regex match:
			StatusCode.RESPONDER + ',' + StatusCode.NO_AVAILABLE_IDP + ",No IDP,invalid_status,access_denied",
			// regex match with capturing group and namespace removal:
			StatusCode.RESPONDER + ',' + StatusCode.AUTHN_FAILED + ",Failed,invalid_status,authn_failed",
			// regex match with capturing group:
			StatusCode.RESPONDER + ',' + StatusCode.PROXY_COUNT_EXCEEDED + ",Failed,invalid_status,proxy_count_exceeded",
			// auth server error matching:
			StatusCode.RESPONDER + ",urn:unknown,Failed,invalid_status,server_error",
			// fallback to namespace:
			StatusCode.RESPONDER + ",test:namespace:SampleCode,Sample,some_error,ns_sample_code"
	}, nullValues = "null")
	void mapSamlStatusToOidcByRegex(String statusCode, String nestedStatusCode, String message,
			String authServerErrorCode, String expected) {
		var properties = new OidcProperties();
		properties.setSamlErrorCodeRegexMappings(givenRegexes());
		properties.setSamlNamespacesMappedToOidcFormat(givenNamespaces());
		assertThat(SamlStatusCode.toOidcErrorCode(properties, statusCode, nestedStatusCode, message, authServerErrorCode),
				is(expected));
	}

	@Test
	void mapSamlStatusToOidcNoProperties() {
		assertThat(
				SamlStatusCode.toOidcErrorCode(null, StatusCode.UNKNOWN_PRINCIPAL, "anything", "goes", "invalid_status,"),
				is(nullValue()));
		assertThat(
				SamlStatusCode.toOidcErrorCode(new OidcProperties(), StatusCode.UNKNOWN_PRINCIPAL, "anything", "goes", "invalid_status,"),
				is(nullValue()));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,null",
			"PwdResetFailed,example,urn:example:names:tc:SAML:2.0:status:PwdResetFailed",
			"PwdResetFailed,null,urn:oasis:names:tc:SAML:2.0:status:PwdResetFailed",
			StatusCode.RESPONDER + ",null," + StatusCode.RESPONDER,
			StatusCode.RESPONDER + ",example," + StatusCode.RESPONDER,
			"Other,other,urn:oasis:names:tc:SAML:2.0:status:Other",
			"urn:other:names:tc:SAML:2.0:status:Other,other,urn:other:names:tc:SAML:2.0:status:Other"
	}, nullValues = "null")
	void addDefaultNamespace(String id, String prefix, String expected) {
		var properties = givenSamlProperties();
		assertThat(SamlStatusCode.addNamespace(properties, id, prefix), is(expected));
	}

	@Test
	void addDefaultNamespaceMissingData() {
		var code = "TestCode";
		assertThat(SamlStatusCode.addNamespace(null, code, null), is(code));
		assertThat(SamlStatusCode.addNamespace(new SamlProperties(), code, null), is(code));
		assertThat(SamlStatusCode.addNamespace(new SamlProperties(), code, "any"), is(code));
	}

	@Test
	void addDefaultNamespaceFallbackToFirstNamespace() {
		var properties = new SamlProperties();
		properties.setFlowPolicyNamespaces(givenNamespaces());
		properties.getFlowPolicyNamespaces().get(1).setPrefix("oasis");
		assertThat(SamlStatusCode.addNamespace(properties, "ExampleStatus", "any"),
				is("urn:example:names:tc:SAML:2.0:status:ExampleStatus"));
	}

	private static SamlProperties givenSamlProperties() {
		var properties = new SamlProperties();
		properties.setFlowPolicyNamespaces(givenNamespaces());
		return properties;
	}

	private static List<SamlNamespace> givenNamespaces() {
		var exampleNs = new SamlNamespace("urn:example:names:tc:SAML:2.0:status", "example");
		var oasisNs = new SamlNamespace("urn:oasis:names:tc:SAML:2.0:status", null);
		var test = new SamlNamespace("test:namespace:SampleCode", "ns");
		return List.of(exampleNs, oasisNs, test);
	}

	private static List<RegexNameValue> givenRegexes() {
		return List.of(
			// ignored:
			RegexNameValue.builder().build(),
			// string
			RegexNameValue.builder().regex(StatusCode.UNKNOWN_PRINCIPAL).value("unauthorized_client").build(),
			// regex with value
			RegexNameValue.builder().regex("urn:oasis:names:tc:SAML:2.0:status:No.*").value("access_denied").build(),
			// regex with capturing group
			RegexNameValue.builder().regex("(urn:oasis:names:tc:SAML:2.0:status:Auth.*)$").build(),
			// regex with capturing group
			RegexNameValue.builder().regex("urn:oasis:names:tc:SAML:2.0:status:(.*)$").build(),
			// mapping auth server error codde
			RegexNameValue.builder().regex("invalid_status").value("server_error").build()
		);
	}

}
