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

package swiss.trustbroker.wstrustclient.xml;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.soap.wstrust.impl.AbstractWSTrustObjectMarshaller;
import org.w3c.dom.Element;

public class ClaimTypeMarshaller extends AbstractWSTrustObjectMarshaller {

	@Override
	protected void marshallAttributes(final XMLObject xmlObject, final Element domElement) throws MarshallingException {
		final ClaimType claimType = (ClaimType) xmlObject;
		if (claimType.getUri() != null) {
			domElement.setAttributeNS(null, ClaimType.URI_ATTRIB_NAME, claimType.getUri());
		}
		if (claimType.getOptional() != null) {
			domElement.setAttributeNS(null, ClaimType.OPTIONAL_ATTRIB_NAME, claimType.getOptional());
		}

		XMLObjectSupport.marshallAttributeMap(claimType.getUnknownAttributes(), domElement);
	}

}
