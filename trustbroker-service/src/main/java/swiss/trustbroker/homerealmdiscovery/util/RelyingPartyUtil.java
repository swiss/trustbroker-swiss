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

package swiss.trustbroker.homerealmdiscovery.util;

import java.util.ArrayList;
import java.util.List;

public class RelyingPartyUtil {

	private RelyingPartyUtil() {}

	// Implements the referrer addressing approach.
	// Clients can be identified in configuration via the host:port/path of their referer header, not the URN in AuthnRequest
	public static List<String> getIdsFromReferer(String refererUrl) {
		List<String> refererIds = new ArrayList<>();
		if (refererUrl != null && (refererUrl.startsWith("http://") || refererUrl.startsWith("https://"))) {
			refererIds.add(refererUrl);
			refererUrl = refererUrl.replaceAll("\\?.*", "");    // cut query
			var urlParts = refererUrl.split("/");
			if (urlParts.length >= 5) {
				refererIds.add(urlParts[2] + "/" + urlParts[3] + "/" + urlParts[4]); // host:port/path/path
			}
			if (urlParts.length >= 4) {
				refererIds.add(urlParts[2] + "/" + urlParts[3]); // host:port/path
			}
			if (urlParts.length >= 3) {
				refererIds.add(urlParts[2]); // host:port
			}
		}
		return refererIds;
	}

	public static String getApplicationFromProfiledRole(String profiledRole) {
		// profileId\role
		String[] attributes = profiledRole.split("\\\\");
		if (attributes.length > 1) {
			return attributes[1];
		}
		return profiledRole;
	}

}
