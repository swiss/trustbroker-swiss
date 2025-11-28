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

package swiss.trustbroker.common.saml.util;

public class SamlContextClass {

	public static final String MOBILE_ONE_FACTOR_UNREGISTERED =
			"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorUnregistered";

	public static final String PASSWORD_PROTECTED_TRANSPORT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

	public static final String SOFTWARE_TIME_SYNC_TOKEN = "urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwareTimeSyncToken";

	public static final String NOMAD_TELEPHONY = "urn:oasis:names:tc:SAML:2.0:ac:classes:NomadTelephony";

	public static final String KERBEROS = "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos";

	public static final String SOFTWARE_PKI = "urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI";

	public static final String MOBILE_TWO_FACTOR_CONTACT = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract";

	public static final String TIME_SYNC_TOKEN = "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken";

	public static final String SMART_CARD_PKI = "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI";

	public static final String UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";

	private SamlContextClass() {
	}

}
