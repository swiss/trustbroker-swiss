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

package swiss.trustbroker.ldap.model;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.naming.NamingException;

import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.DirContextAdapter;

public class LdapAttributeMapper implements ContextMapper<Map<String, List<String>>> {

	@Override
	public Map<String, List<String>> mapFromContext(Object ctx) throws NamingException {
		final var context = (DirContextAdapter) ctx;
		Map<String, List<String>> attributeMap = new HashMap<>();
		final var ids = context.getAttributes().getIDs();
		while (ids.hasMore()) {
			final var attrId = ids.next();
			attributeMap.put(attrId, Arrays.asList(context.getStringAttributes(attrId)));
		}
		return attributeMap;
	}

}
