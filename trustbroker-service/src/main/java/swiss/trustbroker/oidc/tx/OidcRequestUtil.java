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

package swiss.trustbroker.oidc.tx;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class OidcRequestUtil {

	private static final String SCOPE_PARAM = "scope";

	OidcRequestUtil() {
	}

	static Map<String, String[]> cleanScopeParamSpaces(Map<String, String[]> requestParameterMap) {
		Map<String, String[]> parameterMap = new HashMap<>(requestParameterMap);
		if (parameterMap.containsKey(SCOPE_PARAM)) {
			String[] scopes = cleanParam(parameterMap.get(SCOPE_PARAM));
			parameterMap.put(SCOPE_PARAM, scopes);
		}
		return parameterMap;
	}

	static String[] cleanScopeParamSpaces(String[] param, String name) {
		if (Objects.equals(name, SCOPE_PARAM)) {
			return cleanParam(param);
		}
		return param;
	}

	private static String[] cleanParam(String[] param) {
		for (int i = 0; i < param.length; i++) {
			param[i] = param[i].trim().replaceAll(" +", " ");
		}
		return param;
	}

}
