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
import static org.hamcrest.Matchers.sameInstance;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class CollectionUtilTest {

	@Test
	void asCollection() {
		assertThat(CollectionUtil.asCollection(null), is(Collections.emptyList()));
		var str = "test";
		assertThat(CollectionUtil.asCollection(str), is(List.of(str)));
		var set = Set.of(str);
		assertThat(CollectionUtil.asCollection(set), is(sameInstance(set)));
	}

	@Test
	void asList() {
		assertThat(CollectionUtil.asList(null), is(Collections.emptyList()));
		var str = "test";
		assertThat(CollectionUtil.asList(str), is(List.of(str)));
		var set = Set.of(str);
		assertThat(CollectionUtil.asList(set), is(List.of(str)));
		var list = List.of(str);
		assertThat(CollectionUtil.asList(list), is(sameInstance(list)));
	}

	@Test
	void collectionAsSet() {
		var collection = List.of("1", "2", "2", "3");
		var expected = Set.of("1", "2", "3");
		assertThat(CollectionUtil.collectionAsSet(expected), sameInstance(expected));
		assertThat(CollectionUtil.collectionAsSet(collection), is(expected));
	}

	@Test
	void asMap() {
		var key = "key";
		var value = "value";
		var oldValue = "oldValue";
		var map = Map.of(key, value);
		assertThat(CollectionUtil.asMap(null, null, map), is(sameInstance(map)));
		assertThat(CollectionUtil.asMap(key, value, map), is(sameInstance(map)));
		assertThat(CollectionUtil.asMap(key, value, oldValue), is(Map.of(key, value)));
	}

	@Test
	void addToListIfNotExist() {
		assertThat(CollectionUtil.addToListIfNotExist(List.of(1, 2, 4, 6), List.of(3, 4, 5, 6)), is(List.of(1, 2, 4, 6, 3, 5)));
	}

	@Test
	void toStringList() {
		assertThat(CollectionUtil.toStringList(null, Object::toString), is(nullValue()));

		List<Boolean> list = new ArrayList<>(List.of(Boolean.TRUE, Boolean.FALSE));
		list.add(null);

		var result = CollectionUtil.toStringList(list, Object::toString);

		List<String> expected = new ArrayList<>(List.of("true", "false"));
		expected.add(null);
		assertThat(result, is(expected));
	}

	@ParameterizedTest
	@MethodSource
	void findListByPredicate(List<String> values, List<String> expected, Optional<String> expectedSingle) {
		var result = CollectionUtil.findListByPredicate(values, CollectionUtilTest::isMatching);
		assertThat(result, is(expected));
		var single = CollectionUtil.findSingleValueByPredicate(values, CollectionUtilTest::isMatching);
		assertThat(single, is(expectedSingle));
	}

	static Object[][] findListByPredicate() {
		return new Object[][] {
				{ null, Collections.emptyList(), Optional.empty() },
				{
					List.of("drop1", "keep1", "drop2", "keep2", "drop3"),
					List.of("keep1", "keep2"), Optional.of("keep1")
				}
		};
	}

	private static boolean isMatching(String value) {
		return value.startsWith("keep");
	}

	@ParameterizedTest
	@MethodSource
	void getSingleValue(List<String> values, String expected) {
		assertThat(CollectionUtil.getSingleValue(values, "test"), is(expected));
	}

	static Object[][] getSingleValue() {
		return new Object[][] {
				{ null, null },
				{ Collections.emptyList(), null },
				{ List.of("Test"), "Test" }
		};
	}

	@ParameterizedTest
	@MethodSource
	void getSingleValueFromMap(Optional<Map.Entry<String, List<String>>> entry, String expected) {
		assertThat(CollectionUtil.getSingleValue(entry), is(expected));
	}

	static Object[][] getSingleValueFromMap() {
		return new Object[][] {
				{ Optional.empty(), null },
				{ Optional.of(new AbstractMap.SimpleEntry<>("key", Collections.emptyList())), null },
				{ Optional.of(new AbstractMap.SimpleEntry<>("key", List.of("value1", "value2"))), "value1" }
		};
	}

	@Test
	void getKey() {
		assertThat(CollectionUtil.getKey(Optional.empty()), is(nullValue()));
		assertThat(CollectionUtil.getKey(Optional.of(new AbstractMap.SimpleEntry<>("key", "value"))), is("key"));
	}

	@Test
	void getList() {
		assertThat(CollectionUtil.getList(Optional.empty()), is(Collections.emptyList()));
		List<String> value = List.of("value");
		assertThat(CollectionUtil.getList(Optional.of(new AbstractMap.SimpleEntry<>("key", value))), is(value));
	}

	@ParameterizedTest
	@MethodSource
	void toLogString(Collection<String> values, String expected) {
		assertThat(CollectionUtil.toLogString(values), is(expected));
	}

	static Object[][] toLogString() {
		return new Object[][] {
				{ null, "null" },
				{ Collections.emptyList(), "[]" },
				{ List.of("a", "bc", "d"), "[a, bc, d]" },
				{ Set.of("a"), "[a]" }
		};
	}

}
