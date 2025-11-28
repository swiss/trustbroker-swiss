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

package swiss.trustbroker.common.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.exception.ErrorMarker;
import swiss.trustbroker.common.exception.ExceptionUtil;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.VelocityUtil;

@SpringBootTest
@ContextConfiguration(classes = {
		VelocityEngine.class
})
class VelocityUtilTest {

	private static final String TEMPLATE = "/templates/Template.vm";

	@MockitoBean
	private VelocityEngine mockEngine;

	@Test
	void populateVelocityContext() {
		var data = Map.of("key1", "value1", "key2", "value2");
		var context = new VelocityContext();

		VelocityUtil.populateVelocityContext(context, data);

		for (var entry : data.entrySet()) {
			assertThat(context.get(entry.getKey()), is(entry.getValue()));
		}
	}

	@Test
	void renderTemplate() throws Exception {
		var engine = OpenSamlUtil.createVelocityEngine(null);
		var response = new MockHttpServletResponse();
		var data = Map.of("key1", "value1", "key2", "value2");

		VelocityUtil.renderTemplate(engine, response, TEMPLATE, data);

		assertThat(response.getContentAsString(), is("One: value1\nTwo: value2"));
	}

	@ParameterizedTest
	@MethodSource
	void renderTemplateBrokenPipe(Exception ex, ErrorMarker errorMarker) {
		var response = new MockHttpServletResponse();
		Map<String, Object> contextValues = Collections.emptyMap();
		doThrow(ex).when(mockEngine).mergeTemplate(eq(TEMPLATE), any(), any(), any());
		var thrown = assertThrows(TechnicalException.class,
				() -> VelocityUtil.renderTemplate(mockEngine, response, TEMPLATE, contextValues));
		assertThat(thrown.getErrorMarker(), is(errorMarker));
	}

	static Object[][] renderTemplateBrokenPipe() {
		return new Object[][] {
				{ new RuntimeException("Failed", new IOException(ExceptionUtil.BROKEN_PIPE)), ErrorMarker.CLIENT_DISCONNECT },
				{ new RuntimeException("Failed", new IOException("Other")), ErrorMarker.DEFAULT }
		};
	}
}
