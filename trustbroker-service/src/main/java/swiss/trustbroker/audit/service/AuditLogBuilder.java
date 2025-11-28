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

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.audit.dto.AuditDto;
import swiss.trustbroker.audit.dto.CustomLogging;

/**
 * Build log entry for audit log in expected format: <code>key=value[,key=value ...]</code>. Value is enclosed in double quotes if
 * needed (currently: if not alphanumeric or underscore). Double quotes in value escaped with a backslash. <br/> A postfix can be
 * added in the value (used for fully qualified names): <code>key="value (postfix)"</code> <br/> Dashes in the key name are
 * replaced with underscores to comply with Splunk key requirements.
 */
public class AuditLogBuilder {

	// https://docs.splunk.com/Documentation/Splunk/latest/Data/Configureindex-timefieldextraction
	// (values might allow more characters without quoting)
	private static final Pattern KEY_NAME_PATTERN = Pattern.compile("\\w*");

	private final AuditLogFilter filter;

	private final StringBuilder output = new StringBuilder();

	private final int prefixLength;

	private final List<Field> dtoFields;

	public AuditLogBuilder(AuditLogFilter filter) {
		this(filter, null);
	}

	public AuditLogBuilder(AuditLogFilter filter, String prefix) {
		this.filter = filter;
		if (prefix != null) {
			output.append(prefix);
		}
		prefixLength = output.length();
		dtoFields = initDtoFields();
	}

	@SuppressWarnings("java:S3011") // modifying field accessibility in local dto package
	private static List<Field> initDtoFields() {
		// operates on a copy of the declared fields and makes them accessible for this class
		List<Field> dtoFieldList = new ArrayList<>();
		for (Field field : AuditDto.class.getDeclaredFields()) {
			// some fields need special handling
			if (!Modifier.isStatic(field.getModifiers()) && field.getAnnotation(CustomLogging.class) == null) {
				field.setAccessible(true);
				dtoFieldList.add(field);
			}
		}
		return dtoFieldList;
	}

	// not used for OIDC
	private boolean isAuditAddonsEnabled(AuditDto.ResponseAttributeValue attributeValue) {
		return filter.isAdditionalAuditingEnabled() && // DEBUG
				(StringUtils.isNotEmpty(attributeValue.getNamespaceUri())  // SAML name
						|| attributeValue.hasSourceTag()); // SAML value
	}

	/**
	 * Append key/value pair in the format specified above.
	 *
	 * @param name         nothing appended if null (should not happen in practice)
	 * @param attributeValues
	 * value        nothing appended if null (i.e. skip key if no value present)
	 * namespaceUri appended after value if not null or empty
	 * source       short name appended if set
	 * @return this
	 */
	private AuditLogBuilder appendValues(String name, List<AuditDto.ResponseAttributeValue> attributeValues) {
		if (name == null || CollectionUtils.isEmpty(attributeValues)) {
			return this;
		}
		if (output.length() > prefixLength) {
			output.append(", ");
		}
		// some AttributeNames contain dash, which is not allowed as Splunk key character for indexing -> replace to avoid quotes
		appendEncoded(name.replace('-', '_'));
		output.append('=');
		var valueBuilder = new StringBuilder();
		// flatten singleton list
		if (attributeValues.size() == 1) {
			appendValue(valueBuilder, attributeValues.get(0));
		}
		else {
			var separator = "[";
			for (var attributeValue : attributeValues) {
				valueBuilder.append(separator);
				separator = ", ";
				appendValue(valueBuilder, attributeValue);
			}
			valueBuilder.append("]");
		}
		appendEncoded(valueBuilder.toString());
		return this;
	}

	private void appendValue(StringBuilder valueBuilder, AuditDto.ResponseAttributeValue attributeValue) {
		valueBuilder.append(valueToString(attributeValue.getValue()));
		// if not INFO we append the FQ name to see from which attribute this was mapped plus some stats
		if (isAuditAddonsEnabled(attributeValue)) {
			valueBuilder.append(" (");
			var subSeparator = "";
			if ((attributeValue.hasSourceTag())) {
				valueBuilder.append('@');
				if (attributeValue.getSource().getShortName() != null) {
					valueBuilder.append(attributeValue.getSource().getShortName());
				}
				if (attributeValue.getQuerySource() != null) {
					valueBuilder.append('/');
					valueBuilder.append(attributeValue.getQuerySource());
				}
				subSeparator = " ";
			}
			if (attributeValue.getNamespaceUri() != null) {
				valueBuilder.append(subSeparator);
				valueBuilder.append(attributeValue.getNamespaceUri());
			}
			valueBuilder.append(')');
		}
	}

	public AuditLogBuilder append(String key, Object value, String postfix) {
		if (value == null || filter.suppressField(key, value)) {
			return this;
		}
		return appendValues(key,
				Collections.singletonList(AuditDto.ResponseAttributeValue.of(value, postfix, null, null, null)));
	}

	private void appendEncoded(String value) {
		String valueStr = value.replace("\"", "\\\"");
		boolean simpleValue = KEY_NAME_PATTERN.matcher(valueStr).matches();
		if (!simpleValue) {
			output.append('"');
		}
		output.append(valueStr);
		if (!simpleValue) {
			output.append('"');
		}
	}

	public AuditLogBuilder append(String key, Object value) {
		return append(key, value, null);
	}

	private static String valueToString(Object value) {
		if (value instanceof Collection) {
			Collection<?> col = (Collection<?>) value;
			if (col.size() == 1) {
				// name="value1" in Splunk
				return String.valueOf(col.iterator().next());
			}
			if (col.isEmpty()) {
				// null or empty string better for Splunk? null could be a value produced before so use name="" for now
				return "";
			}
			// else: name="[value1, value2]" in Splunk (for sets/lists - for maps {key1=value1 key2=value2} -> not yet used)
		}
		return String.valueOf(value);
	}

	/**
	 * append all fields of the AuditDto
	 *
	 * @param auditDto
	 * @return this
	 */
	public AuditLogBuilder appendDtoFields(AuditDto auditDto) {
		if (auditDto == null) {
			return this;
		}
		dtoFields.forEach(field -> appendField(auditDto, field));
		return this;
	}

	private void appendField(AuditDto auditDto, Field field) {
		try {
			appendField(field.getName(), field.get(auditDto));
		}
		catch (IllegalAccessException ex) {
			// does not happen as we made them accessible
		}
	}

	private void appendField(String key, Object value) {
		if (filter.suppressField(key, value)) {
			return;
		}
		if (value instanceof Map) {
			appendMapEntries((Map<?, ?>) value);
		}
		else {
			append(key, value);
		}
	}

	private void appendMapEntries(Map<?, ?> values) {
		// map is broken down into individual key/value pairs
		values.forEach((key, value) -> {
			var keyString = String.valueOf(key);
			if (value instanceof AuditDto.ResponseAttributeValues attributeValues) {
				var filteredValues = attributeValues.getValues().stream()
						.filter(attributeValue -> attributeValue.getValue() != null)
						.filter(attributeValue -> !filter.suppressAttribute(keyString, attributeValue))
						.toList();
				appendValues(keyString, filteredValues);
			}
			else {
				append(keyString, value);
			}
		});
	}

	public String build() {
		return output.toString();
	}

	@Override
	public String toString() {
		return output.toString();
	}
}
