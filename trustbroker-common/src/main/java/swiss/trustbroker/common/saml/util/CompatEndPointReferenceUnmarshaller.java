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

import javax.annotation.Nonnull;
import javax.xml.namespace.QName;

import lombok.extern.slf4j.Slf4j;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.soap.wsfed.Address;
import org.opensaml.soap.wsfed.EndPointReference;
import org.opensaml.soap.wsfed.WSFedConstants;
import org.opensaml.soap.wsfed.impl.EndPointReferenceUnmarshaller;

/**
 * Unmarshaller for opensaml4 compatibility that can handle this nesting:
 * <pre>
 * <wsa:EndPointReference xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
 *   <wsa:Address xmlns:wsa="http://www.w3.org/2005/08/addressing">urn:SAMPLE_RP</wsa:Address>
 * </wsa:EndPointReference>
 * </pre>
 */
@Slf4j
public class CompatEndPointReferenceUnmarshaller extends EndPointReferenceUnmarshaller {

	public static final QName QNAME =
			new QName(WSFedConstants.WSADDRESS_NS, EndPointReference.class.getSimpleName(), WSFedConstants.WSADDRESS_PREFIX);

	@Override
	protected void processChildElement(@Nonnull XMLObject parentXMLObject, @Nonnull XMLObject childXMLObject)
			throws UnmarshallingException {
		final EndPointReference endPointReference = (EndPointReference) parentXMLObject;
		if (childXMLObject instanceof org.opensaml.soap.wsaddressing.Address wsaddrAddress) {
			log.debug("Backwards compatibility: Accepting wsaddressing.Address nested in wsfed.EndpointReference with addr={}",
					wsaddrAddress.getURI());
			var address = OpenSamlUtil.buildSamlObject(Address.class);
			address.setValue(wsaddrAddress.getURI());
			endPointReference.setAddress(address);
		}
		else {
			super.processChildElement(parentXMLObject, childXMLObject);
		}
	}
}
