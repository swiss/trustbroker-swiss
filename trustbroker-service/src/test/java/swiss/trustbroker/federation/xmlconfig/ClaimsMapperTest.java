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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class ClaimsMapperTest {

	@ParameterizedTest
	@MethodSource
	void mapObjectTimeEpoch(Object input, Object expected) {
		assertThat(ClaimsMapper.TIME_EPOCH.map(input), is(expected));
	}

	static Object[][] mapObjectTimeEpoch() {
		return new Object[][] {
				{ null, null },
				{ "", "" },
				{ "text", "text" },
				{ Boolean.TRUE, Boolean.TRUE },
				{ "01.01.70", "01.01.70" },
				{ "1970-01-01", 0l },
				{ "1970-01-01Z", 0l },
				{ "1970-01-01T01:00:00+01:00[Europe/Paris]", 0l },
				{ "1970-01-01T00:00:00Z", 0l },
				{ "2001-09-09T01:46:40Z", 1_000_000_000l },
				{ "2001-09-09T02:46:40+01:00[Europe/Paris]", 1_000_000_000l },
				{ Instant.ofEpochMilli(1_000_000_000_000l), 1_000_000_000l },
				{ new Date(1_000_000_000_000l), 1_000_000_000l },
				{ "01.01.1970", 0l }, // time zone ignored for date
				{ "01.01.1970 00:00:00", Long.valueOf(-getStartOfEpochZoneoffset().getTotalSeconds()) }
		};
	}

	@ParameterizedTest
	@MethodSource
	void mapObjectTimeIso(Object input, Object expected) {
		assertThat(ClaimsMapper.TIME_ISO.map(input), is(expected));
	}

	static Object[][] mapObjectTimeIso() {
		var startOfEpochZoneoffset = getStartOfEpochZoneoffset();
		var localStartOfEpoch = LocalDate.of(1970, 1, 1)
										 .atStartOfDay()
										 .toInstant(startOfEpochZoneoffset)
										 .toString();
		return new Object[][] {
				{ null, null },
				{ "", "" },
				{ "text", "text" },
				{ Boolean.TRUE, Boolean.TRUE},
				{ "01.01.70", "01.01.70" },
				{ "1970-01-01", "1970-01-01T00:00:00Z" },
				{ "1970-01-01Z", "1970-01-01T00:00:00Z" },
				{ "1970-01-01T01:00:00+01:00[Europe/Paris]", "1970-01-01T00:00:00Z" },
				{ "1970-01-01T00:00:00Z", "1970-01-01T00:00:00Z" },
				{ "2001-09-09T01:46:40Z", "2001-09-09T01:46:40Z" },
				{ "2001-09-09T02:46:40+01:00[Europe/Paris]", "2001-09-09T01:46:40Z" },
				{ Instant.ofEpochMilli(1_000_000_000_000l), "2001-09-09T01:46:40Z" },
				{ new Date(1_000_000_000_000l), "2001-09-09T01:46:40Z" },
				{ "01.01.1970", "1970-01-01T00:00:00Z" }, // time zone ignored
				{ "01.01.1970 00:00:00", localStartOfEpoch },
		};
	}

	private static ZoneOffset getStartOfEpochZoneoffset() {
		var localDateTimeStartOfEpoch = LocalDateTime.of(1970, 1, 1, 0, 0, 0);
		return ZoneOffset.systemDefault().getRules().getOffset(localDateTimeStartOfEpoch);
	}

	@ParameterizedTest
	@MethodSource
	void mapObjectDateIso(Object input, Object expected) {
		assertThat(ClaimsMapper.DATE_ISO.map(input), is(expected));
	}

	static Object[][] mapObjectDateIso() {
		var localStartDayOfEpoch = DateTimeFormatter.ISO_DATE.format(LocalDate.of(1970, 1, 1)
																			  .atStartOfDay()
																			  .atOffset(OffsetDateTime.now().getOffset())
																			  .atZoneSameInstant(ZoneOffset.UTC));
		return new Object[][] {
				{ null, null },
				{ "", "" },
				{ "text", "text" },
				{ Boolean.TRUE, Boolean.TRUE},
				{ "01.01.70", "01.01.70" },
				{ "1970-01-01", "1970-01-01Z" },
				{ "1970-01-01Z", "1970-01-01Z" },
				{ "1970-01-01T01:00:00+01:00[Europe/Paris]", "1970-01-01Z" },
				{ "1970-01-01T00:00:00Z", "1970-01-01Z" },
				{ "2001-09-09T01:46:40Z", "2001-09-09Z" },
				{ "2001-09-09T02:46:40+01:00[Europe/Paris]", "2001-09-09Z" },
				{ Instant.ofEpochMilli(1_000_000_000_000l), "2001-09-09Z" },
				{ new Date(1_000_000_000_000l), "2001-09-09Z" },
				{ "01.01.1970", "1970-01-01Z" }, // time zone ignored
				{ "01.01.1970 00:00:00", localStartDayOfEpoch }
		};
	}

	@ParameterizedTest
	@MethodSource
	void mapObjectDateLocal(Object input, Object expected) {
		assertThat(ClaimsMapper.DATE_LOCAL.map(input), is(expected));
	}

	static Object[][] mapObjectDateLocal() {
		var localStartDayOfEpoch = ClaimsMapper.LOCAL_DATE_FORMATTER.format(LocalDate.of(1970, 1, 1)
																			  .atStartOfDay()
																			  .atOffset(OffsetDateTime.now().getOffset())
																			  .atZoneSameInstant(ZoneOffset.UTC));
		return new Object[][] {
				{ null, null },
				{ "", "" },
				{ "text", "text" },
				{ Boolean.TRUE, Boolean.TRUE},
				{ "01.01.70", "01.01.70" },
				{ "1970-01-01", "1970-01-01" },
				{ "1970-01-01Z", "1970-01-01" },
				{ "1970-01-01T01:00:00+01:00[Europe/Paris]", "1970-01-01" },
				{ "1970-01-01T00:00:00Z", "1970-01-01" },
				{ "2001-09-09T01:46:40Z", "2001-09-09" },
				{ "2001-09-09T02:46:40+01:00[Europe/Paris]", "2001-09-09" },
				{ Instant.ofEpochMilli(1_000_000_000_000l), "2001-09-09" },
				{ new Date(1_000_000_000_000l), "2001-09-09" },
				{ "01.01.1970", "1970-01-01" }, // time zone ignored
				{ "01.01.1970 00:00:00", localStartDayOfEpoch }
		};
	}

	@ParameterizedTest
	@MethodSource
	void mapObjectTimeBoolean(Object input, Object expected) {
		assertThat(ClaimsMapper.BOOLEAN.map(input), is(expected));
	}

	static Object[][] mapObjectTimeBoolean() {
		return new Object[][] {
				{ null, null },
				{ "", "" },
				{ "text", "text" },
				{ Boolean.TRUE, Boolean.TRUE },
				{ "true", Boolean.TRUE },
				{ "True", Boolean.TRUE },
				{ "TRUE", Boolean.TRUE },
				{ "false", Boolean.FALSE },
				{ "False", Boolean.FALSE },
				{ "FALSE", Boolean.FALSE },
		};
	}

	@ParameterizedTest
	@MethodSource
	void mapObjectTimeSwissSocialSecurityNo(Object input, Object expected) {
		assertThat(ClaimsMapper.SWISS_SOCIAL_SECURITY_NO.map(input), is(expected));
	}

	static Object[][] mapObjectTimeSwissSocialSecurityNo() {
		return new Object[][] {
				{ null, null },
				{ "", "" },
				{ "text", "text" },
				{ Boolean.TRUE, Boolean.TRUE },
				{ "7561234567890", 7561234567890l },
				{ "756.1234.5678.90", 7561234567890l },
				{ "7561234.5678.90", 7561234567890l },
				{ "756.1234.5678.901", "756.1234.5678.901" },
				{ "9756.1234.5678.901", "9756.1234.5678.901" },
		};
	}

	@ParameterizedTest
	@MethodSource
	void mapObjectListTimeEpoch(List<Object> input, Object expected) {
		assertThat(ClaimsMapper.TIME_EPOCH.map(input), is(expected));
	}

	static Object[][] mapObjectListTimeEpoch() {
		return new Object[][] {
				{ null, null },
				{ Collections.emptyList(), Collections.emptyList() },
				{ List.of("test", "1973-03-03T09:46:40Z", Instant.ofEpochMilli(123_456_789l), Integer.MAX_VALUE),
						List.of("test", 100_000_000l, 123_456l, Integer.MAX_VALUE) }
		};
	}

	@ParameterizedTest
	@MethodSource
	void mapObjectListEmail(List<Object> input, Object expected) {
		assertThat(ClaimsMapper.EMAIL.map(input), is(expected));
	}

	static Object[][] mapObjectListEmail() {
		return new Object[][] {
				{ null, null },
				{ Collections.emptyList(), Collections.emptyList() },
				{ List.of("name.name@domain", "name.other@domain"),	List.of("name.name@domain", "name.other@domain") },
				{ List.of("name.name@domain", "Name.Name@domain"),	List.of("name.name@domain") },
				{ List.of("Name.Name@domain", "name.name@domain"),	List.of("name.name@domain") }
		};
	}

}
