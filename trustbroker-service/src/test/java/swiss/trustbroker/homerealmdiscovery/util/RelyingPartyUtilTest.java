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

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class RelyingPartyUtilTest {

	@Test
	void testReferrerUrlHandling() {
		assertEquals(0, RelyingPartyUtil.getIdsFromReferer(null).size());
		assertEquals(0, RelyingPartyUtil.getIdsFromReferer("bullshit").size());
		assertEquals(2, RelyingPartyUtil.getIdsFromReferer("http://host").size());
		assertEquals(2, RelyingPartyUtil.getIdsFromReferer("http://host:80").size());
		assertEquals(2, RelyingPartyUtil.getIdsFromReferer("https://host").size());
		assertEquals(2, RelyingPartyUtil.getIdsFromReferer("https://host:443").size());
		assertEquals(2, RelyingPartyUtil.getIdsFromReferer("https://host:443/").size());
		assertEquals(3, RelyingPartyUtil.getIdsFromReferer("https://host:443/path").size());
		assertEquals(3, RelyingPartyUtil.getIdsFromReferer("https://host:443/path/").size());
		assertEquals(4, RelyingPartyUtil.getIdsFromReferer("https://host:443/path/path").size());
		assertEquals(4, RelyingPartyUtil.getIdsFromReferer("https://host:443/path/path/").size());
		assertEquals(4, RelyingPartyUtil.getIdsFromReferer("https://host:443/path/path/path").size());
		assertEquals(0, RelyingPartyUtil.getIdsFromReferer("https:/host:443/path/path/path").size());
		assertEquals("x/1/2", RelyingPartyUtil.getIdsFromReferer("http://x/1/2/3").get(1));
		assertEquals("x/1", RelyingPartyUtil.getIdsFromReferer("http://x/1/2/3").get(2));
		assertEquals("x", RelyingPartyUtil.getIdsFromReferer("http://x/1/2/3").get(3));
	}

}
