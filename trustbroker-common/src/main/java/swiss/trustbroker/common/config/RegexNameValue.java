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

package swiss.trustbroker.common.config;

import java.util.regex.Pattern;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Data;
import lombok.Setter;
import lombok.ToString;

/**
 * Combination of regular expression, an optional name of an item to match against that regex, and a value to use if matching.
 */
@ToString // required to ToString.Exclude
@Data
@Builder
public class RegexNameValue {

	private String regex;

	private String name;

	private String value;

	@ToString.Exclude
	@Setter(AccessLevel.NONE)
	private Pattern pattern;

	public RegexNameValue() { }

	public RegexNameValue(String regex, String name, String value) {
		this(regex, name, value, null);
	}

	// required for Lombok @Builder:
	public RegexNameValue(String regex, String name, String value, Pattern pattern) {
		if (pattern != null) {
			this.pattern = pattern;
			this.regex = pattern.pattern();
		}
		else {
			setRegex(regex);
		}
		this.name = name;
		this.value = value;
	}

	public void setRegex(String regex) {
		this.regex = regex;
		if (regex == null) {
			pattern = null;
		}
		else {
			pattern = Pattern.compile(regex);
		}
	}
}
