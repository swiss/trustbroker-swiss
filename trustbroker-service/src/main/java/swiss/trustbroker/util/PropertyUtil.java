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

package swiss.trustbroker.util;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;

import org.apache.commons.beanutils.PropertyUtils;
import org.apache.commons.lang3.StringUtils;
import swiss.trustbroker.common.exception.TechnicalException;

/**
 * Java bean property utilities.
 */
public class PropertyUtil {

	private PropertyUtil() {
	}

	/**
	 * Copy all attributes from base to target if set in base, but not in target.
	 * Note: Careful if you have a <code>Boolean</code> with getter <code>Boolean getProperty</code> and
	 * <code>setProperty(Boolean)</code> and a convenience override <code>boolean isProperty</code> a property descriptor
	 * is produced for the <code>boolean isProperty</code> without a setter and the propagation fails!
	 * I.e. don't name the convenience accessors 'is', but leave the 'is' out.
	 */
	public static <X> void copyMissingAttributes(X target, X base) {
		copyMissingAttributes(Collections.emptySet(), target, base);
	}

	/**
	 * Copy all attributes from base to target if set in base, but not in target.
	 */
	public static <X> void copyMissingAttributes(Set<String> propertyNames, X target, X base) {
		if (base == null || target == null || base == target) {
			return;
		}
		if (!target.getClass().isAssignableFrom(base.getClass())) {
			throw new TechnicalException(String.format("Incompatible classes base=%s, target=%s",
					base.getClass().getName(), target.getClass().getName()));
		}
		var unmatchedProperties = new ArrayList<>(propertyNames);
		for (var propertyDescriptor : PropertyUtils.getPropertyDescriptors(base)) {
			if (propertyNames.isEmpty() || propertyNames.contains(propertyDescriptor.getName())) {
				var getter = propertyDescriptor.getReadMethod();
				var setter = propertyDescriptor.getWriteMethod();
				if (getter != null && setter != null) {
					copyAttributeIfMissing(toBiConsumer(setter), toFunction(getter), target, base);
					unmatchedProperties.remove(propertyDescriptor.getName());
				}
			}
		}
		if (!unmatchedProperties.isEmpty()) {
			throw new TechnicalException(String.format("Class=%s is missing writable properties=%s", base.getClass().getName(),
					unmatchedProperties));
		}
	}

	/**
	 * Copy attribute from base to target if set in base, but not in target (blank check).
	 *
	 * @return true if copying was done, false if a merge of the values is needed
	 */
	public static <X> boolean copyAttributeIfBlank(BiConsumer<X, String> setter, Function<X, String> getter, X target, X base) {
		return copyAttributeIfRequired(setter, getter, target, base, StringUtils::isBlank);
	}

	/**
	 * Copy attribute from base to target if set in base, but not in target (null check).
	 *
	 * @return true if copying was done, false if a merge of the values is needed
	 */
	public static <X, Y> boolean copyAttributeIfMissing(BiConsumer<X, Y> setter, Function<X, Y> getter, X target, X base) {
		return copyAttributeIfRequired(setter, getter, target, base, Objects::isNull);
	}

	/**
	 * Copy attribute from base to target if set in base, but not in target (using copyCondition Predicate).
	 *
	 * @return true if copying was done, false if a merge of the values is needed
	 */
	public static <X, Y> boolean copyAttributeIfRequired(BiConsumer<X, Y> setter, Function<X, Y> getter, X target, X base,
			Predicate<Y> copyCondition) {
		if (base == null || target == null || base == target) {
			return true;
		}
		var baseValue = getter.apply(base);
		if (copyCondition.test(baseValue)) {
			return true;
		}
		var targetValue = getter.apply(target);
		if (!copyCondition.test(targetValue)) {
			return false;
		}
		setter.accept(target, baseValue);
		return true;
	}

	@SuppressWarnings("unchecked")
	private static <X, Y> Function<X, Y> toFunction(Method getter) {
		return target -> {
			try {
				return (Y) getter.invoke(target);
			}
			catch (IllegalAccessException | InvocationTargetException ex) {
				throw new TechnicalException(String.format("Could not invoke getter=%s on object of class=%s",
						getter.getName(), target != null ? target.getClass().getName() : "null"), ex);
			}
		};
	}

	private static <X, Y> BiConsumer<X, Y> toBiConsumer(Method setter) {
		return (target, value) -> {
			try {
				setter.invoke(target, value);
			}
			catch (IllegalAccessException | InvocationTargetException ex) {
				throw new TechnicalException(String.format("Could not invoke setter=%s on object of class=%s with value=%s",
						setter.getName(), target != null ? target.getClass().getName() : "null", value), ex);
			}
		};
	}

	@SuppressWarnings("java:S4276") // cannot use Predicate for nullable Boolean
	public static <C, T> T evaluatePropery(C instance,
			Function<C, T> policy, Supplier<T> defaultValue) {
		// default is required (hence a Boolean, to make sure a false value is not from initialization
		if (instance == null) {
			return defaultValue.get();
		}
		var result = policy.apply(instance);
		if (result == null) {
			return defaultValue.get();
		}
		return result;
	}

	public static <C, T extends Number> T evaluatePositiveNumberProperty(C instance,
			Function<C, T> policy, Supplier<T>  defaultValue) {
		var result = evaluatePropery(instance, policy, defaultValue);
		if (result != null && result.longValue() > 0l) {
			return result;
		}
		return defaultValue.get();
	}

}
