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

package swiss.trustbroker.saml.util;

import java.util.Optional;

import swiss.trustbroker.saml.dto.ClaimSource;

public class ClaimSourceUtil {

	public static final String SEPARATOR = ":";

	private ClaimSourceUtil() {
	}

	public static String buildClaimSource(ClaimSource source, String secondarySource) {
		return source.name() + SEPARATOR + secondarySource;
	}

	public static String buildClaimSource(ClaimSource source, ClaimSource secondarySource) {
		return source.name() + SEPARATOR + secondarySource.name();
	}

	public static Optional<String> getSecondarySource(String source, String sourceName) {
		var prefix = sourceName + SEPARATOR;
		if (source.startsWith(prefix)) {
			return Optional.of(source.substring((prefix).length()));
		}
		return Optional.empty();
	}

	public static boolean isCpSource(String cpIssuer, String nameIdSource) {
		if (nameIdSource != null && nameIdSource.startsWith(ClaimSource.CP.name())) {
			Optional<String> secondarySource = ClaimSourceUtil.getSecondarySource(nameIdSource, ClaimSource.CP.name());
			return secondarySource.map(s -> s.equals(cpIssuer)).orElse(true);
		}
		return false;
	}
}
