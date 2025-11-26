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

import java.util.List;
import java.util.Map;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.math.NumberUtils;

/**
 * application.yml config helper methods.
 * <br/>
 * Intended for API implementations to simplify handling of generic Map<String, Object> attributes.
 */
@Slf4j
public class ConfigUtil {

	private ConfigUtil() {}

	/**
	 * Extract value from project for a specific type with an optional default and type coercion for some common
	 * application.yml conversions:
	 * <ul>
	 *     <li>String number to Integer</li>
	 *     <li>String boolean to Boolean</li>
	 *     <li>Number to String</li>
	 *     <li>Map with index as key to List</li>
	 * </ul>
	 */
	public static <T> T getConfig(Map<String, ? extends Object> config, String name, Class<T> resultClass, T defaultValue) {
		var value = config.get(name);
		return getValueAsType(value, resultClass, defaultValue);
	}

	public static String getConfigString(Map<String, ? extends Object> config, String name, String defaultValue) {
		return getConfig(config, name, String.class, defaultValue);
	}

	public static Integer getConfigInteger(Map<String, ? extends Object> config, String name, Integer defaultValue) {
		return getConfig(config, name, Integer.class, defaultValue);
	}

	public static Boolean getConfigBoolean(Map<String, ? extends Object> config, String name, Boolean defaultValue) {
		return getConfig(config, name, Boolean.class, defaultValue);
	}

	@SuppressWarnings("unchecked")
	public static <T> List<T> getConfigList(Map<String, ? extends Object> config, String name, List<T> defaultValue) {
		return getConfig(config, name, List.class, defaultValue);
	}

	@SuppressWarnings("unchecked")
	private static <T> T getValueAsType(Object value, Class<T> resultClass, T defaultValue) {
		if (resultClass.isInstance(value)) {
			return resultClass.cast(value);
		}
		// handle Map<indexString, value> as list
		if (value instanceof Map<?, ?> resultMap && resultClass == List.class) {
			return (T) ((Map<? extends Comparable, ?>) resultMap).entrySet().stream()
					// should not filter, keys are Strings:
					.filter(entry -> entry.getKey() instanceof Comparable)
					// sort by indexString to preserve order:
					.sorted((c1, c2) -> c1.getKey().compareTo(c2.getKey()))
					.map(Map.Entry::getValue)
					.toList();
		}
		// handle non-quoted string that was parsed as number
		if ((value instanceof Number || value instanceof Boolean) && resultClass == String.class) {
			return (T) value.toString();
		}
		// handle quoted string that can be parsed as number
		if (value instanceof String valueStr && Integer.class.isAssignableFrom(resultClass)) {
			return (T) Integer.valueOf(NumberUtils.toInt(valueStr, defaultValue != null ? (Integer) defaultValue : 0));
		}
		// handle quoted boolean that can be parsed as number
		if (value instanceof String valueStr && Boolean.class.isAssignableFrom(resultClass)) {
			return (T) Boolean.valueOf(valueStr);
		}
		if (value != null) {
			log.warn("idm.attributes.{} has class={} expectedClass={} value={}",
					value.getClass().getName(), resultClass.getName(), value);
		}
		return defaultValue;
	}
}
