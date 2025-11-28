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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;

@Slf4j
public class CollectionUtil {

	private CollectionUtil() {
	}

	// returns value converted to (empty if null) list if needed
	@SuppressWarnings("unchecked")
	public static List<Object> asList(Object value) {
		if (value == null) {
			return Collections.emptyList();
		}
		if (value instanceof List<?> list) {
			return (List<Object>) list;
		}
		if (value instanceof Collection<?> collection) {
			return new ArrayList<>(collection);
		}
		var list = new ArrayList<>();
		list.add(value);
		return list;
	}

	// returns oldValue if a Map or else map of name => value (either oldValue or both name and value need to be non-null)
	@SuppressWarnings("unchecked")
	public static Map<String, Object> asMap(String name, Object value, Object oldValue) {
		if (oldValue instanceof Map<?, ?> map) {
			return (Map<String, Object>) map;
		}
		return Map.of(name, value);
	}

	// returns value if a Set or else converts value to set
	public static Set<String> collectionAsSet(Collection<String> value) {
		if (value instanceof Set<String> set) {
			return set;
		}
		return new HashSet<>(value);
	}

	// returns value converted to (empty if null) collection if needed
	@SuppressWarnings("unchecked")
	public static Collection<Object> asCollection(Object value) {
		if (value == null) {
			return Collections.emptyList();
		}
		if (value instanceof Collection<?> collection) {
			return (Collection<Object>) collection;
		}
		var list = new ArrayList<>();
		list.add(value);
		return list;
	}

	// Immutable List.of used everywhere
	// Cf. Apache commons CollectionUtils.union, which returns a sorted list as a Collection with deduplication.
	public static <T> List<T> addToListIfNotExist(List<T> immutableList, List<T> values) {
		var result = new ArrayList<>(immutableList);
		for (var value : values) {
			if (!immutableList.contains(value)) {
				result.add(value);
			}
		}
		return result;
	}

	// convert via toString
	@SuppressWarnings("java:S1168") // generic method converts null input to null output, not to empty list
	public static <T> List<String> toStringList(List<T> values, Function<T, String> converter) {
		if (values == null) {
			return null;
		}
		return values.stream().map(value -> value != null ? converter.apply(value) : null).toList();
	}

	// convert to array string format for logging
	public static String toLogString(Collection<?> collection) {
		if (collection == null) {
			return String.valueOf(collection);
		}
		return toLogString(collection.toArray());
	}

	// convert to array string format for logging
	// (use instead of Arrays.toString so we could change the format for both collections and arrays in one place)
	public static String toLogString(Object[] array) {
		return Arrays.toString(array);
	}

		// cf. Spring CollectionUtils.firstElement which does the same except for the ambiguity logging
	public static <T, K> T getSingleValue(List<T> list, K nameForTracing) {
		if (CollectionUtils.isEmpty(list)) {
			return null;
		}
		if (list.size() > 1) {
			log.info("Potential ambiguity: Picking first value for name={} from values={}", nameForTracing, list);
		}
		return list.get(0);
	}

	public static <K, T> T getSingleValue(Optional<Map.Entry<K, List<T>>> entry) {
		var values = getList(entry);
		return getSingleValue(values, getKey(entry));
	}

	public static <K, T> List<T> getList(Optional<Map.Entry<K, List<T>>> entry) {
		return entry.isPresent() ? entry.get().getValue() : Collections.emptyList();
	}

	public static <K, T> K getKey(Optional<Map.Entry<K, T>> entry) {
		return entry.isPresent() ? entry.get().getKey() : null;
	}

	public static <K> Optional<K> findSingleValueByPredicate(List<K> values, Predicate<K> check) {
		if (values == null) {
			return Optional.empty();
		}
		return values.stream().filter(check).findFirst();
	}

	public static <K> List<K> findListByPredicate(List<K> values, Predicate<K> check) {
		if (values == null) {
			return Collections.emptyList();
		}
		return values.stream().filter(check).toList();
	}

}
