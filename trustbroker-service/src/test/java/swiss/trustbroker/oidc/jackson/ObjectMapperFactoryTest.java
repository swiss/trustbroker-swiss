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

package swiss.trustbroker.oidc.jackson;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.Test;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;

class ObjectMapperFactoryTest {

	@Test
	void testSimpleSaveLoad() throws JsonProcessingException {
		var mapper = ObjectMapperFactory.springSecObjectMapper();
		var expected = "TEST";
		var encoded = mapper.writeValueAsString(expected);
		var decoded = mapper.readValue(encoded, expected.getClass());
		assertThat(decoded, equalTo(expected));
	}

	@Test
	void testAcceptableDataSaveLoad() throws JsonProcessingException {
		var mapper = ObjectMapperFactory.springSecObjectMapper();
		var claims = new HashMap<String, List<Object>>();
		claims.put("emptyArrayList", new ArrayList<>());
		claims.put("emptyList", Collections.emptyList());
		claims.put("immutableList", List.of("TEST1"));
		claims.put("epocTime", List.of(Long.MIN_VALUE));
		var encoded = mapper.writeValueAsString(claims);
		var decoded = mapper.readValue(encoded, claims.getClass());
		assertThat(decoded.size(), equalTo(claims.size()));
	}

	@Test
	void testSaml2Principal() throws JsonProcessingException {
		var mapper = ObjectMapperFactory.springSecObjectMapper();
		var attrs = new HashMap<String, List<Object>>();
		var vals = new ArrayList<>();
		vals.add("VAL1");
		vals.add("VAL2");
		attrs.put("multiValued", vals);
		var principal = new DefaultSaml2AuthenticatedPrincipal("TEST", attrs);
		var encoded = mapper.writeValueAsString(principal);
		var decoded = mapper.readValue(encoded, principal.getClass());
		assertThat(decoded.getAttributes().size(), equalTo(attrs.size()));
	}

}
