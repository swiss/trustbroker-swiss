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

package swiss.trustbroker.federation.xmlconfig;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import jakarta.xml.bind.annotation.adapters.XmlAdapter;

public class StringListAdapter extends XmlAdapter<String, List<String>> {

	private static final String DELIMITER = ",";

	@Override
	public List<String> unmarshal(String value) {
		return Arrays.stream(value.split(DELIMITER))
					 .map(String::trim)
					 .toList();
	}

	@Override
	public String marshal(List<String> values) {
		return values.stream()
					 .map(String::trim)
					 .collect(Collectors.joining(DELIMITER));
	}
}
