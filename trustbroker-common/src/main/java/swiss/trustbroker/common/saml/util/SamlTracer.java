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

package swiss.trustbroker.common.saml.util;

import lombok.extern.slf4j.Slf4j;
import org.opensaml.core.xml.XMLObject;
import org.slf4j.Logger;
import org.w3c.dom.Node;

@Slf4j
public class SamlTracer {

	private SamlTracer() { }

	public static void logSamlObject(final String infoPrefix, final XMLObject xmlObject) {
		logSamlObject(infoPrefix, xmlObject, log);
	}

	public static void logSamlObject(final String infoPrefix, final XMLObject xmlObject, Logger logger) {
		if (logger.isDebugEnabled()) {
			logger.debug( "{}\n{}", infoPrefix, OpenSamlUtil.samlObjectToString(xmlObject, true, true));
		}
	}

	public static void logSoapObject(final String infoPrefix, final Node node) {
		logSoapObject(infoPrefix, node, log);
	}

	public static void logSoapObject(final String infoPrefix, final Node node, Logger logger) {
		if (logger.isDebugEnabled()) {
			logger.debug( "{}\n{}", infoPrefix, SoapUtil.nodeObjectToString(node, true, true));
		}
	}

}
