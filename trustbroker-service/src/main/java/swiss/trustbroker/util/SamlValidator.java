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

package swiss.trustbroker.util;

import java.io.IOException;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.xml.XMLConstants;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.common.xml.SAMLSchemaBuilder;
import org.springframework.stereotype.Component;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;

@Component
@Slf4j
public class SamlValidator {

	private static final String XMLNS_XS = XMLConstants.XMLNS_PREFIX + ":xs";

	// SAMLSchemaBuilder.baseXMLSchemas is private
	private static final String[] BASE_XML_SCHEMAS = {
			SAMLConstants.XML_SCHEMA_LOCATION,
			SAMLConstants.XSD_SCHEMA_LOCATION,
			SAMLConstants.XMLSIG_SCHEMA_LOCATION,
			SAMLConstants.XMLENC_SCHEMA_LOCATION,
			SAMLConstants.XMLSIG11_SCHEMA_LOCATION,
			SAMLConstants.XMLENC11_SCHEMA_LOCATION,
			SAMLConstants.SAML20_SCHEMA_LOCATION // not in SAMLSchemaBuilder.baseXMLSchemas
	};

	private static final String HARDENED_SAML_SCHEMA = "/schema/saml-schema-protocol-HARDENED-2.0.xsd";


	// ThreadLocal uses a stale entry collection algorithm on set and the tomcat worker pool is fixed, we expect 200 entries max
	@SuppressWarnings({ "java:S5164", "java:S3749" })
	private final ThreadLocal<Validator> samlValidatorCache = new ThreadLocal<>();

	// https://wiki.shibboleth.net/confluence/display/OpenSAML/OSTwoUserManJavaValidation
	// loadtest shows all kinds of exception from arry violations, schema violations and NPEs
	// docs says:  A validator object is not thread-safe and not reentrant.
	// We cache because schema preparation is usually an expensive operation, but we did not profile it.
	private Validator getValidator() throws SAXException {
		Validator validator = samlValidatorCache.get();
		if (validator == null) {
			var samlSchema = getSchemaForHardenedXsd();
			validator = samlSchema.newValidator();
			samlValidatorCache.set(validator);
		}
		return validator;
	}

	@SuppressWarnings("java:S1144")
	private static Schema getOpenSamlSchema() throws SAXException {
		var samlSchemaBuilder = new SAMLSchemaBuilder(SAMLSchemaBuilder.SAML1Version.SAML_11);
		return samlSchemaBuilder.getSAMLSchema();
	}

	private static Schema getSchemaForHardenedXsd() throws SAXException {
		// do not allow external schema resolution!
		var factory = SchemaFactory.newInstance(javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
		factory.setProperty(javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD, "");
		factory.setProperty(javax.xml.XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
		// lists of schemas in SAMLSchemaBuilder are private
		var sources = new Source[BASE_XML_SCHEMAS.length + 1];
		int no = 0;
		for (String source : BASE_XML_SCHEMAS) {
			sources[no++] = schemaSource(SAMLSchemaBuilder.class, source);
		}
		sources[no] = schemaSource(SamlValidator.class, HARDENED_SAML_SCHEMA);
		return factory.newSchema(sources);
	}

	private static StreamSource schemaSource(Class<?> baseClass, String schema) {
		return new StreamSource(baseClass.getResourceAsStream(schema));
	}

	@SuppressWarnings("java:S2139") // log exception with SAML context, which we don't want to throw
	public void validateSamlSchema(SAMLObject samlObject) {
		if (samlObject == null) {
			throw new TechnicalException("SAML object missing");
		}
		try {
			validateSamlSchema(samlObject.getDOM());
		}
		catch (Exception e) {
			// Xerces threading issues under load => show stack trace along with the data
			log.error("SAML Schema validation failed with: {} on: {}", e, OpenSamlUtil.samlObjectToString(samlObject));
			throw new RequestDeniedException("SAML Schema validation failed", e);
		}
	}

	@SuppressWarnings("java:S5852") // regexp runs on exception message created by Xerces, matching xs only once for the prefix.
	private void validateSamlSchema(Element dom) throws SAXException, IOException {
		var validator = getValidator();
		try {
			var metadataNode = new DOMSource(dom);
			validator.validate(metadataNode);
		}
		catch (SAXException e) {
			// workaround for a CP that includes "xs:" elements without declaring the xs namespace
			// only try the workaround if the message indicates the namespace prefix is missing
			// (ugly check, depends on XML parser implementation)
			// alternatively we could check for dom.hasAttributeNS(XMLConstants.XML_NS, XMLNS_XS)
			// but sometimes the namespace alias is different (e.g. XMLConstants.XSD_PREFIX is common too) or not needed at all
			var message = e.getMessage();
			if (message != null && !message.matches("UndeclaredPrefix:.*'xs:[^']*'.*")) {
				throw e;
			}
			// log use of workaround in case it causes problems
			log.info("Workaround: SAMLObject is missing namespace alias {}, trying to validate again with that", XMLNS_XS);
			// operate on a clone as we might use this DOM object later to validate the signature
			var clone = (Element)dom.cloneNode(true);
			clone.setAttributeNS(XMLConstants.XMLNS_NS, XMLNS_XS, XMLConstants.XSD_NS);
			var metadataNode = new DOMSource(clone);
			validator.validate(metadataNode);
		}
	}

}
