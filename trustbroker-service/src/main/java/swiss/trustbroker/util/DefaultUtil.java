/*
 * Copyright (C) 2026 trustbroker.swiss team BIT
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

package swiss.trustbroker.util;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.util.Collection;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderSetup;
import swiss.trustbroker.federation.xmlconfig.Default;
import swiss.trustbroker.federation.xmlconfig.RelyingPartySetup;

/**
 * Handle default values defined via <code>@Default</code> annotation.
 *
 * @see Default
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
@Slf4j
public class DefaultUtil {

	private static final Set<String> ALLOWED_PACKAGES = Set.of(Default.class.getPackageName());

	public static void applyCpDefaults(ClaimsProviderSetup claimsProviderSetup) {
		Set<Object> visited = Collections.newSetFromMap(new IdentityHashMap<>());
		if (claimsProviderSetup != null && claimsProviderSetup.getClaimsParties() != null) {
			for (var cp : claimsProviderSetup.getClaimsParties()) {
				log.trace("Applying defaults to cpIssuerId={}", cp.getId());
				applyDefaultValues(cp, visited);
			}
		}
	}

	public static void applyRpDefaults(RelyingPartySetup relyingPartySetup) {
		Set<Object> visited = Collections.newSetFromMap(new IdentityHashMap<>());
		if (relyingPartySetup != null && relyingPartySetup.getRelyingParties() != null) {
			for (var rp : relyingPartySetup.getRelyingParties()) {
				log.trace("Applying defaults to rpIssuerId={}", rp.getId());
				applyDefaultValues(rp, visited);
			}
		}
	}

	public static void applyDefaultValues(Object obj, Set<Object> visited) {
		if (obj == null || visited.contains(obj)) {
			return;
		}
		visited.add(obj);

		Class<?> clazz = obj.getClass();
		if (obj instanceof Collection<?> col) {
			processCollections(visited, col);
		}
		else if (clazz.isArray()) {
			processArray(visited, obj);
		}
		else if (isUnsupportedPackage(clazz)) {
			log.trace("Ignoring class={}= not in allowedPackages={}", clazz.getName(), ALLOWED_PACKAGES);
			return;
		}

		for (var field : clazz.getDeclaredFields()) {
			processField(obj, visited, field);
		}
	}

	@SuppressWarnings("java:S3011")
	private static void processField(Object obj, Set<Object> visited, Field field) {
		try {
			Object value = getValue(obj, field);
			if (value == null) {
				return;
			}

			Class<?> valueType = value.getClass();
			if (value instanceof Collection<?> col) {
				processCollections(visited, col);
			}
			else if (valueType.isArray()) {
				processArray(visited, value);
			}
			else if (isSimpleType(valueType)) {
				log.trace("Ignoring class={} value='{}'", valueType.getName(), value);
			}
			else if (isUnsupportedPackage(valueType)) {
				log.trace("Ignoring class={} value='{}' not in allowedPackages={}", valueType.getName(), value,
						ALLOWED_PACKAGES);
			}
			else {
				applyDefaultValues(value, visited);
			}
		}
		catch (IllegalAccessException e) {
			throw new TechnicalException(String.format("Could not apply default value to class=%s object=%s",
					obj.getClass()
					   .getName(), obj), e);
		}
	}

	private static void processArray(Set<Object> visited, Object value) {
		var len = Array.getLength(value);
		for (var i = 0; i < len; i++) {
			applyDefaultValues(Array.get(value, i), visited);
		}
	}

	private static void processCollections(Set<Object> visited, Collection<?> col) {
		for (var element : col) {
			applyDefaultValues(element, visited);
		}
	}

	@SuppressWarnings("java:S3011")
	private static Object getValue(Object obj, Field field) throws IllegalAccessException {
		field.setAccessible(true);
		var value = field.get(obj);
		var def = field.getAnnotation(Default.class);
		if (value == null && def != null) {
			var converted = convert(def.value(), field.getType());
			log.trace("Setting default {}.{}='{}'", obj.getClass().getName(), field.getName(), converted);
			field.set(obj, converted);
			value = converted;
		}
		return value;
	}

	private static boolean isSimpleType(Class<?> type) {
		return type.isPrimitive()
				|| type.equals(String.class)
				|| Number.class.isAssignableFrom(type)
				|| type.equals(Boolean.class)
				|| type.equals(Character.class)
				|| type.isEnum();
	}

	private static Object convert(String value, Class<?> type) {
		if (type == Boolean.class || type == boolean.class) {
			return Boolean.valueOf(value);
		}
		if (type == Integer.class || type == int.class) {
			return Integer.valueOf(value);
		}
		if (type == Long.class || type == long.class) {
			return Long.valueOf(value);
		}
		if (type == String.class) {
			return value;
		}
		throw new TechnicalException(String.format("Unsupported type: %s", type.getName()));
	}

	private static boolean isUnsupportedPackage(Class<?> type) {
		var pkg = type.getPackageName();
		return ALLOWED_PACKAGES.stream().noneMatch(pkg::startsWith);
	}
}
