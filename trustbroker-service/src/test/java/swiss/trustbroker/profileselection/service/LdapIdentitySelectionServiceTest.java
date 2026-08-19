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

package swiss.trustbroker.profileselection.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.util.ApiSupport;

@SpringBootTest(properties = {
		"trustbroker.config.ldap.enabled=true",
		"trustbroker.config.profileselection.enabled=true"
})
@ContextConfiguration(classes = { LdapIdentitySelectionService.class })
class LdapIdentitySelectionServiceTest {

	@MockitoBean
	private ApiSupport apiSupport;

	@Autowired
	protected LdapIdentitySelectionService ldapIdentitySelectionService;

	@ParameterizedTest
	@CsvSource({
			"profileId,profileId,true",
			"profileId,userId,false",
			"profileId,userName:uniteName,false",
			"profileId:user,profileId,true",
			"profileId:user,unitName,false",
			"profileId:org:memberOf,profileId,true",
			"profileId:org:memberOf,unitName,false",
			"profileId:org:memberOf,profileId:org,true",
			"profileId:org:memberOf,profileId:org2,false",
			"profileId:org2:memberOf,profileId:org,false",
			"profileId:org:memberOf,unit,false"
	})
	void testIsProfileAttribute(String profileAttr, String profilePrefix, boolean expected) {
		boolean result = LdapIdentitySelectionService.isProfileAttribute(profileAttr, profilePrefix);
		assertEquals(expected, result);
	}

}
