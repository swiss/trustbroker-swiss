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

import javax.xml.namespace.QName;

import org.opensaml.core.xml.AttributeExtensibleXMLObject;
import org.opensaml.soap.wstrust.WSTrustObject;

public interface ClaimType extends AttributeExtensibleXMLObject, WSTrustObject {

	public static final String IDENTITY_NS = "http://schemas.xmlsoap.org/ws/2005/05/identity";

	public static final String IDENTITY_PREFIX = "ic";

	public static final String ELEMENT_LOCAL_NAME = "ClaimType";

	public static final QName ELEMENT_NAME =
			new QName(IDENTITY_NS, ELEMENT_LOCAL_NAME, IDENTITY_PREFIX);

	public static final String TYPE_LOCAL_NAME = "ClaimsTypeType";

	public static final QName TYPE_NAME =
			new QName(IDENTITY_NS, TYPE_LOCAL_NAME, IDENTITY_PREFIX);

	public static final String URI_ATTRIB_NAME = "Uri";

	public static final String OPTIONAL_ATTRIB_NAME = "Optional";

	public String getUri();

	public void setUri(String uri);

	public String getOptional();

	public void setOptional(String optional);

	// convenience method
	public void setOptionalBoolean(Boolean optional);

}
