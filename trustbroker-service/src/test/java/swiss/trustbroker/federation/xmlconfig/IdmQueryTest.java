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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doReturn;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.api.idm.dto.IdmRequest;

@SpringBootTest
@ContextConfiguration(classes = { IdmRequest.class })
class IdmQueryTest {

	private static final String ATTRIBUTE_NAME = "attribute1";

	@MockitoBean
	private IdmRequest idmRequest;

	@Test
	void testIdmRequestConversion() {
		var selection = AttributesSelection.builder()
				.definitions(List.of(Definition.builder().name(ATTRIBUTE_NAME).build()))
				.build();
		var idmQuery = IdmQuery.builder()
							   .id("query1")
							   .name("name1")
							   .issuerNameId("issuerNameId1")
							   .issuerNameIdNS("https://trustbroker.swiss/issuerNameId")
							   .subjectNameId("subjectNameId1")
							   .clientExtId("clientExtId1")
							   .appFilter("app1")
							   .statusPolicy(StatusPolicy.BLOCK)
							   .userDetailsSelection(selection)
							   .build();

		// IdmQuery is not copied
		var same = IdmQuery.of(idmQuery);
		assertSame(same, idmQuery);

		doReturn(idmQuery.getId()).when(idmRequest).getId();
		doReturn(idmQuery.getName()).when(idmRequest).getName();
		doReturn(idmQuery.getIssuerNameIdAttribute()).when(idmRequest).getIssuerNameIdAttribute();
		doReturn(idmQuery.getSubjectNameIdAttribute()).when(idmRequest).getSubjectNameIdAttribute();
		doReturn(idmQuery.getClientExtId()).when(idmRequest).getClientExtId();
		doReturn(idmQuery.getAppFilter()).when(idmRequest).getAppFilter();
		doReturn(idmQuery.getUserStatusPolicy()).when(idmRequest).getUserStatusPolicy();
		doReturn(idmQuery.getAttributeSelection()).when(idmRequest).getAttributeSelection();

		var copy = IdmQuery.of(idmRequest);

		assertEquals(copy, idmQuery);
	}

	@Test
	void testStatusPolicy() {
		var query = IdmQuery.builder().build();
		assertThat(query.statusPolicyWithDefault(), is(StatusPolicy.FETCH_ACTIVE_ONLY));
		assertThat(query.getUserStatusPolicy(), is(StatusPolicy.FETCH_ACTIVE_ONLY.name()));
		assertThat(query.isFetchActiveOnly(), is(true));

		query.setStatusPolicy(StatusPolicy.FETCH_ACTIVE_ONLY);
		assertThat(query.isFetchActiveOnly(), is(true));

		query.setStatusPolicy(StatusPolicy.BLOCK);
		assertThat(query.isFetchActiveOnly(), is(false));
		assertThat(query.statusPolicyWithDefault(), is(StatusPolicy.BLOCK));
	}

	@Test
	void testAttributeSelection() {
		var definition = Definition.builder().name(ATTRIBUTE_NAME).build();
		var query = IdmQuery.builder().build();

		var attributeSelectionEmptyImmutable = query.getAttributeSelection();
		assertThat(attributeSelectionEmptyImmutable, hasSize(0));
		assertThrows(UnsupportedOperationException.class, () -> attributeSelectionEmptyImmutable.add(definition));

		var selection = AttributesSelection.builder()
										   .definitions(List.of(definition))
										   .build();
		query.setUserDetailsSelection(selection);

		var attributeSelectionImmutable = query.getAttributeSelection();
		assertThat(attributeSelectionImmutable, hasSize(1));
		assertThat(attributeSelectionImmutable.get(0).getName(), is(ATTRIBUTE_NAME));
		assertThrows(UnsupportedOperationException.class, () -> attributeSelectionImmutable.add(definition));
	}
}
