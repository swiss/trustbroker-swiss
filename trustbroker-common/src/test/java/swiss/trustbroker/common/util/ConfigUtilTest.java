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
import static org.hamcrest.Matchers.nullValue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class ConfigUtilTest {

	@Test
	void getConfigString() {
		var config = createConfigMap();
		assertThat(ConfigUtil.getConfigString(config, "missingString", null), is(nullValue()));
		assertThat(ConfigUtil.getConfigString(config, "missingString", "defaultValue"), is("defaultValue"));
		assertThat(ConfigUtil.getConfigString(config, "aString", null), is("aStringValue"));
		assertThat(ConfigUtil.getConfigString(config, "aNumber", null), is("10"));
		assertThat(ConfigUtil.getConfigString(config, "aBoolean", null), is("true"));
		assertThat(ConfigUtil.getConfigString(config, "anObject", "fallback"), is("fallback"));
	}

	@Test
	void getConfigInt() {
		var config = createConfigMap();
		assertThat(ConfigUtil.getConfigInteger(config, "missingNumber", null), is(nullValue()));
		assertThat(ConfigUtil.getConfigInteger(config, "missingNumber", 20), is(Integer.valueOf(20)));
		assertThat(ConfigUtil.getConfigInteger(config, "aNumber", null), is(10));
		assertThat(ConfigUtil.getConfigInteger(config, "numberString", null), is(15));
		assertThat(ConfigUtil.getConfigInteger(config, "numberString", 42), is(15));
	}

	@Test
	void getConfigBoolean() {
		var config = createConfigMap();
		assertThat(ConfigUtil.getConfigBoolean(config, "missingBoolean", null), is(nullValue()));
		assertThat(ConfigUtil.getConfigBoolean(config, "missingBoolean", true), is(Boolean.TRUE));
		assertThat(ConfigUtil.getConfigBoolean(config, "aBoolean", null), is(Boolean.TRUE));
		assertThat(ConfigUtil.getConfigBoolean(config, "booleanString", null), is(Boolean.TRUE));
	}

	@Test
	void getConfigList() {
		var config = createConfigMap();
		assertThat(ConfigUtil.getConfigList(config, "missingList", null), is(nullValue()));
		assertThat(ConfigUtil.getConfigList(config, "missingList", List.of("default")), is(List.of("default")));
		assertThat(ConfigUtil.getConfigList(config, "aList", null), is(List.of("value1", "value2")));
		assertThat(ConfigUtil.getConfigList(config, "mapList", null), is(List.of("value1", "value2")));
		assertThat(ConfigUtil.getConfigList(config, "mapMapList", null),
				is(List.of(Map.of("key1", "value1"), Map.of("key2", "value2"))));
	}

	private static Map<String, Object> createConfigMap() {
		return Map.of(
				"aString", "aStringValue",
				"aNumber", 10,
				"numberString", "15",
				"aBoolean", true,
				"booleanString", "true",
				"aList", List.of("value1", "value2"),
				"mapList", Map.of("0", "value1", "1", "value2"),
				"mapMapList", Map.of("0", Map.of("key1", "value1"), "1", Map.of("key2", "value2")),
				"anObject", new Object()
		);
	}

}
