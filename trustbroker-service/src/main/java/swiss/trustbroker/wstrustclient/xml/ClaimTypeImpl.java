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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.util.AttributeMap;
import org.opensaml.core.xml.util.IndexedXMLObjectChildrenList;
import org.opensaml.soap.wstrust.impl.AbstractWSTrustObject;

public class ClaimTypeImpl extends AbstractWSTrustObject implements ClaimType {

	private String uri;

	private String optional;

	private IndexedXMLObjectChildrenList<XMLObject> unknownChildren;

	private AttributeMap unknownAttributes;


	public ClaimTypeImpl(final String namespaceURI, final String elementLocalName, final String namespacePrefix) {
		super(namespaceURI, elementLocalName, namespacePrefix);
		unknownChildren = new IndexedXMLObjectChildrenList<>(this);
		unknownAttributes = new AttributeMap(this);
	}

	public AttributeMap getUnknownAttributes() {
		return unknownAttributes;
	}

	public List<XMLObject> getOrderedChildren() {
		final ArrayList<XMLObject> children = new ArrayList<>();
		children.addAll(unknownChildren);
		return Collections.unmodifiableList(children);
	}

	@Override
	public String getUri() {
		return uri;
	}

	@Override
	public void setUri(String uri) {
		this.uri = uri;
	}

	@Override
	public String getOptional() {
		return optional;
	}

	@Override
	public void setOptional(String optional) {
		this.optional = optional;
	}

	@Override
	public void setOptionalBoolean(Boolean optional) { this.optional = optional == null ? null : optional.toString(); }

	public static void registerObjectProvider() {
		var providerRegistry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		providerRegistry.registerObjectProvider(ELEMENT_NAME, new ClaimTypeBuilder(),
				new ClaimTypeMarshaller(), new ClaimTypeUnmarshaller());
	}
}
