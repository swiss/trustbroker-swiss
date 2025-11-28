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

package swiss.trustbroker.config;

import swiss.trustbroker.homerealmdiscovery.util.RelyingPartySetupUtil;

/**
 * Constants for tests.
 */
public class TestConstants {

	// directory structure

	public static final String CACHE_PATH = "cache/";

	public static final String CACHE_DEFINITION_PATH = CACHE_PATH + RelyingPartySetupUtil.DEFINITION_PATH;

	public static final String LATEST_PATH = "latest/";

	public static final String LATEST_DEFINITION_PATH = LATEST_PATH + RelyingPartySetupUtil.DEFINITION_PATH;

	public static final String LATEST_INVALID_DEFINITION_PATH = LATEST_PATH + "invalid_definition/";

	// XML config files

	public static final String TEST_BASE_PROFILE = "ProfileRP_Standard.xml";

	public static final String TEST_BASE_STANDARD = TestConstants.LATEST_DEFINITION_PATH + TEST_BASE_PROFILE;

	public static final String TEST_SETUP_RP = TestConstants.LATEST_DEFINITION_PATH + "SetupRP.xml";

	public static final int VALID_TEST_RPS = 24;

	public static final int INVALID_TEST_RPS = 1;

	public static final String TEST_SETUP_CP = TestConstants.LATEST_DEFINITION_PATH + "SetupCP.xml";

	public static final int VALID_TEST_CPS = 4;

	public static final String TEST_CP_DEFINITIONS = TestConstants.LATEST_DEFINITION_PATH + "ClaimsProviderDefinitions.xml";

	public static final String TEST_SSO_GROUP_SETUP = TestConstants.LATEST_DEFINITION_PATH + "SetupSSOGroups.xml";

	public static final String TEST_SETUP_RP_INVALID_XML = LATEST_DEFINITION_PATH + "SetupRPInvalidXml.xml";

	public static final String TEST_RULE_WITH_CACHE_BASE_DEFINITIONS =
			LATEST_DEFINITION_PATH + "RuleDefinitionWithCachedBase.xml";

	public static final String TEST_CACHE_BASE_RULE = "ProfileRP_Standard2.xml";

}
