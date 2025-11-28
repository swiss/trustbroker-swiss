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

package swiss.trustbroker.audit.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doReturn;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.audit.dto.AuditDto;
import swiss.trustbroker.audit.dto.EventType;

@SpringBootTest(classes = AuditLogFilter.class)
class AuditLogBuilderTest {

	@MockitoBean
	private AuditLogFilter filter;

	@BeforeEach
	void setUp() {
		doReturn(true).when(filter).isAdditionalAuditingEnabled();
	}

	@Test
	void testEmpty() {
		AuditLogBuilder auditLogBuilder = new AuditLogBuilder(filter);
		String result = auditLogBuilder.build();
		assertThat(result, is(""));
	}

	@Test
	void testPrefix() {
		String prefix = "something";
		AuditLogBuilder auditLogBuilder = new AuditLogBuilder(filter, prefix);
		String result = auditLogBuilder.build();
		assertThat(result, is(prefix));
	}

	@ParameterizedTest
	@CsvSource({
			",value,postfix,",
			"key,,postfix,",
			"simple,something,,simple=something",
			"dashes-to-underscores,value-with-dashes-quoted,,dashes_to_underscores=\"value-with-dashes-quoted\"",
			"space key,space value,,\"space key\"=\"space value\"",
			"astring,The quick brown fox,,astring=\"The quick brown fox\"",
			"\"quoted\" value,A \"special\" case,,\"\\\"quoted\\\" value\"=\"A \\\"special\\\" case\"",
			"name,value,postfix,name=\"value (postfix)\"",
	})
	void testKeyValue(String key, String value, String postfix, String expected) {
		AuditLogBuilder auditLogBuilder = new AuditLogBuilder(filter);
		auditLogBuilder.append(key, value, postfix);
		String result = auditLogBuilder.build();
		if (expected == null) {
			expected = ""; // empty string for expected, but null for inputs -> cannot use CsvSource.emptyValue
		}
		assertThat(result, is(expected));
	}

	@Test
	void testList() {
		AuditLogBuilder auditLogBuilder = new AuditLogBuilder(filter);
		auditLogBuilder.append("roles", List.of("one", "two", "three"));
		String result = auditLogBuilder.build();
		assertThat(result, is("roles=\"[one, two, three]\""));
	}

	@Test
	void testSet() {
		AuditLogBuilder auditLogBuilder = new AuditLogBuilder(filter);
		Set<Integer> set = new TreeSet<>(); // ensure stable toString with TreeSet
		set.add(1);
		set.add(2);
		auditLogBuilder.append("roles", set);
		String result = auditLogBuilder.build();
		assertThat(result, is("roles=\"[1, 2]\""));
	}

	@Test
	void testMap() {
		AuditLogBuilder auditLogBuilder = new AuditLogBuilder(filter);
		Map<String, List<String>> map = new TreeMap<>(); // ensure stable toString with TreeMap
		map.put("key1", List.of("one"));
		map.put("key2", List.of("two, three"));
		auditLogBuilder.append("complex", map);
		String result = auditLogBuilder.build();
		assertThat(result, is("complex=\"{key1=[one], key2=[two, three]}\""));
	}

	@Test
	void testSingletonList() {
		AuditLogBuilder auditLogBuilder = new AuditLogBuilder(filter);
		auditLogBuilder.append("roles", Collections.singletonList("theoneandonly"));
		String result = auditLogBuilder.build();
		assertThat(result, is("roles=theoneandonly"));
	}

	@Test
	void testEmptySet() {
		AuditLogBuilder auditLogBuilder = new AuditLogBuilder(filter);
		auditLogBuilder.append("roles", Collections.emptySet());
		String result = auditLogBuilder.build();
		assertThat(result, is("roles="));
	}

	@Test
	void testCombined() {
		AuditLogBuilder auditLogBuilder = new AuditLogBuilder(filter, "Test line: ");
		auditLogBuilder.append("url", "https://example.trustbroker.swiss/api?test");
		auditLogBuilder.append("count", 42);
		auditLogBuilder.append("name", "John Doe");
		auditLogBuilder.append("login", "X12345678");
		String result = auditLogBuilder.build();
		assertThat(result, is("Test line: url=\"https://example.trustbroker.swiss/api?test\", count=42, name=\"John Doe\", login=X12345678"));
	}

	@Test
	void testAppendDto() {
		var auditDto = AuditDto.builder()
				.conversationId("1af312")
				.destination("target")
				.billingId("suppressed")
				.eventType(EventType.RESPONSE)
				.responseAttributes(Map.of(
						"custom",
								AuditDto.ResponseAttributeValues.of(AuditDto.ResponseAttributeValue.of(
										List.of("single"), null, AuditDto.AttributeSource.CP_RESPONSE, null, false)),
						"nullValue", AuditDto.ResponseAttributeValues.of(AuditDto.ResponseAttributeValue.of(
								null, "nothing", AuditDto.AttributeSource.CP_RESPONSE, null, false)),
						"filtered", AuditDto.ResponseAttributeValues.of(AuditDto.ResponseAttributeValue.of(
								List.of("ok"), "any", AuditDto.AttributeSource.CP_RESPONSE, null, true)),
						"decided", AuditDto.ResponseAttributeValues.of(AuditDto.ResponseAttributeValue.of(
								List.of("yes", "no"), "/ns/maybe", AuditDto.AttributeSource.CP_RESPONSE, null, false)),
						"multi",
							AuditDto.ResponseAttributeValues.of(
									AuditDto.ResponseAttributeValue.of(
											List.of("one"), null, AuditDto.AttributeSource.IDM_RESPONSE, "global", false),
									AuditDto.ResponseAttributeValue.of(
											List.of("other"), null, AuditDto.AttributeSource.IDM_RESPONSE, "tenant", false))
				))
				.build();
		doReturn(true).when(filter).suppressAttribute(any(), argThat(AuditDto.ResponseAttributeValue::getCid));
		doReturn(true).when(filter).suppressField(argThat(arg -> arg.equals("billingId")), any());
		var auditLogBuilder = new AuditLogBuilder(filter);
		auditLogBuilder.appendDtoFields(auditDto);
		var result = auditLogBuilder.build();
		assertThat(result, containsString("conversationId=1af312"));
		assertThat(result, containsString("destination=target"));
		assertThat(result, containsString("custom=\"single (@c)\""));
		assertThat(result, containsString("decided=\"[yes, no] (@c /ns/maybe)\""));
		assertThat(result, containsString("multi=\"[one (@i/global), other (@i/tenant)]\""));
		assertThat(result, not(containsString("filtered=")));
		assertThat(result, not(containsString("nullValue=")));
		assertThat(result, not(containsString("billingId=")));
	}

}
