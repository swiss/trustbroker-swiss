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

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.Temporal;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.EnumUtils;

/**
 * Mapping of OIDC/SAML claims.
 */
@Slf4j
public enum ClaimsMapper {

	/**
	 * Maps ISO-8601 datetime or instant string or Date/Instant to epoc seconds.
 	 */
	TIME_EPOCH {

		public Object map(Object value) {
			var temporal = toTemporal(value);
			if (temporal instanceof Instant instant) {
				return instant.getEpochSecond();
			}
			if (temporal instanceof LocalDate localDate) {
				// date only, calculate as if in UTC
				return TimeUnit.DAYS.toSeconds(localDate.toEpochDay());
			}
			if (temporal instanceof LocalDateTime localDateTime) {
				return localDateTime.toInstant(getOffset(localDateTime)).getEpochSecond();
			}
			unexpectedValue(value, this.name());
			return value;
		}
	},

	/**
	 * Maps ISO-8601 datetime or instant string or Date/Instant to ISO-8601 instant string.
	 *
	 * @since 1.10.0
	 */
	TIME_ISO {

		public Object map(Object value) {
			var temporal = toTemporal(value);
			if (temporal instanceof Instant instant) {
				return DateTimeFormatter.ISO_INSTANT.format(instant);
			}
			if (temporal instanceof LocalDate localDate) {
				// date only, calculate as if in UTC
				return DateTimeFormatter.ISO_INSTANT.format(localDate.atStartOfDay().atOffset(ZoneOffset.UTC));
			}
			if (temporal instanceof LocalDateTime localDateTime) {
				return DateTimeFormatter.ISO_INSTANT.format(localDateTime.atOffset(getOffset(localDateTime)));
			}
			unexpectedValue(value, this.name());
			return value;
		}

	},

	/**
	 * Maps ISO-8601 date or instant string or Date/Instant to ISO-8601 date string.
	 *
	 * @since 1.10.0
	 */
	DATE_ISO {

		public Object map(Object value) {
			return mapDate(DateTimeFormatter.ISO_DATE, value, this.name());
		}

	},

	/**
	 * Maps ISO-8601 date or instant string or Date/Instant to ISO-8601 like date string without time zone.
	 *
	 * @since 1.10.0
	 */
	DATE_LOCAL {

		public Object map(Object value) {
			return mapDate(LOCAL_DATE_FORMATTER, value, this.name());
		}

	},

	/**
	 * Maps "true"/"false" (case-insensitive) to Boolean.
 	 */
	BOOLEAN {

		public Object map(Object value) {
			if (value instanceof String valueStr) {
				if (valueStr.equalsIgnoreCase("true")) {
					return Boolean.TRUE;
				}
				if (valueStr.equalsIgnoreCase("false")) {
					return Boolean.FALSE;
				}
			}
			else if (value instanceof Boolean) {
				return value;
			}
			unexpectedValue(value, this.name());
			return value;
		}

	},

	/**
	 * Maps swiss social security number to Long:<br/>
	 * three digits (currently always 756) optional dot, 4 digits, optional dot, 4 digits, optional dot, 2 digits.
 	 */
	SWISS_SOCIAL_SECURITY_NO {

		private static final Pattern PATTERN = Pattern.compile("\\d\\d\\d[.]?\\d\\d\\d\\d[.]?\\d\\d\\d\\d[.]?\\d\\d");

		public Object map(Object value) {
			if (value instanceof String valueStr) {
				if (PATTERN.matcher(valueStr).matches()) {
					valueStr = valueStr.replace(".", "");
					// must be parseable as long now
					return Long.parseLong(valueStr);
				}
			}
			else if (value instanceof Number) {
				return value;
			}
			unexpectedValue(value, this.name());
			return value;
		}

	},

	/**
	 * Runs a Groovy script to perform the mapping: name-converter.groovy
	 */
	SCRIPT {
		// must be done post-processing as we do not have a ScriptService here and script name needs to be derived
		public Object map(Object value) {
			return value;
		}
	},

	/**
	 * Normalize emails dropping duplicates (same value from different sources).
	 * Experimental: RFC 5321 actually says mails can have a case-sensitive local-part but in practice it's case-insensitive.
	 */
	EMAIL {
		public Object map(Object value) {
			return value == null ? null : value.toString().toLowerCase();
		}
	},

	/**
	 * Ignore attribute for response.
	 *
	 * @since 1.10.0
	 */
	IGNORE {
		public Object map(Object value) {
			return null;
		}
	},

	/**
	 * Transform attribute to String.
	 *
	 * @since 1.10.0
	 */
	STRING {
		public Object map(Object value) {
			return value == null ? null : String.valueOf(value);
		}
	};

	static final DateTimeFormatter LOCAL_DATE_FORMATTER = DateTimeFormatter.ofPattern("uuuu-MM-dd");

	private static final List<Function<String, Temporal>> PARSERS = List.of(
			str -> parseInstant(DateTimeFormatter.ISO_INSTANT, str),
			str -> parseInstant(DateTimeFormatter.ISO_DATE_TIME, str),
			str -> parseLocalDate(DateTimeFormatter.ISO_DATE, str),
			str -> parseLocalDate(LOCAL_DATE_FORMATTER, str),
			str -> parseLocalDate(DateTimeFormatter.ofPattern("dd.MM.uuuu"), str),
			str -> parseLocalDateTime(DateTimeFormatter.ofPattern("dd.MM.uuuu HH:mm:ss"), str)
	);

	private static Instant parseInstant(DateTimeFormatter formatter, String valueStr) {
		return formatter.parse(valueStr, Instant::from);
	}

	private static LocalDateTime parseLocalDateTime(DateTimeFormatter formatter, String valueStr) {
		return formatter.parse(valueStr, LocalDateTime::from);
	}

	private static LocalDate parseLocalDate(DateTimeFormatter formatter, String valueStr) {
		return formatter.parse(valueStr, LocalDate::from);
	}

	// input date time format has no time zone - use system default, i.e. assuming the caller is in the same zone
	private static ZoneOffset getOffset(LocalDateTime localDateTime) {
		return ZoneId.systemDefault()
					 .getRules()
					 .getOffset(localDateTime);
	}

	public abstract Object map(Object value);

	@SuppressWarnings("java:S1168") // mapper does not know the semantics of the list, hence it must map a null list to null
	public List<Object> map(List<Object> values) {
		if (values == null) {
			return null;
		}
		// optionally make value unique for some mapper types
		List<Object> list =  values.stream()
				.map(this::map)
				.filter(Objects::nonNull)
				.flatMap(v -> v instanceof List<?> ? ((List<?>) v).stream() : Stream.of(v))
				.toList();
		return optionalUnique(list);
	}

	private List<Object> optionalUnique(List<Object> values) {
		if (this.equals(EMAIL)) {
			return values.stream()
					.distinct()
					.toList();
		}
		return values;
	}

	private static void unexpectedValue(Object value, String mapper) {
		if (value != null) {
			log.info("Invalid value=\"{}\" of type={} for oidcMapper={} returning unchanged",
					value, value.getClass().getName(), mapper);
		}
	}

	public static ClaimsMapper of(String name) {
		var result = EnumUtils.getEnum(ClaimsMapper.class, name);
		if (result == null) {
			log.error("Invalid mapper={} allowedValues={}", name, values());
		}
		return result;
	}

	private static Temporal toTemporal(Object value) {
		if (value instanceof String valueStr) {
			List<Exception> exceptions = new ArrayList<>();
			for (var parser : PARSERS) {
				try {
					return parser.apply(valueStr);
				}
				catch (DateTimeParseException ex) {
					exceptions.add(ex);
				}
			}
			// collect all parsing issues
			var exMessages = exceptions.stream().map(Exception::getMessage).collect(Collectors.joining());
			log.info("Cannot parse value=\"{}\" as ISO-8601 datetime/instant or 'dd.MM.yyyy [HH:mm:ss]': {}",value, exMessages);
		}
		else if (value instanceof Instant valueInstant) {
			return valueInstant;
		}
		else if (value instanceof Date valueDate) {
			return Instant.ofEpochMilli(valueDate.getTime());
		}
		return null;
	}

	private static Object mapDate(DateTimeFormatter formatter, Object value, String mapperName) {
		var temporal = toTemporal(value);
		if (temporal instanceof Instant instant) {
			return formatter.format(instant.atOffset(ZoneOffset.UTC));
		}
		if (temporal instanceof LocalDate localDate) {
			// date only, calculate as if in UTC
			return formatter.format(localDate.atStartOfDay()
											 .atOffset(ZoneOffset.UTC));
		}
		if (temporal instanceof LocalDateTime localDateTime) {
			// assume local time zone, convert to UTC
			var dateTime = localDateTime.atOffset(ClaimsMapper.getOffset(localDateTime))
										.atZoneSameInstant(ZoneOffset.UTC);
			return formatter.format(dateTime);
		}
		unexpectedValue(value, mapperName);
		return value;
	}
}
