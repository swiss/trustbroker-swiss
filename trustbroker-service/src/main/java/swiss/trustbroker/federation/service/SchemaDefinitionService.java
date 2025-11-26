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

package swiss.trustbroker.federation.service;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AnnotationTypeFilter;
import org.springframework.stereotype.Service;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.federation.controller.XmlConfigController;
import swiss.trustbroker.federation.xmlconfig.RelyingPartySetup;

/**
 * Service for loading the XSD schemas.
 */
@Service
@Slf4j
public class SchemaDefinitionService {

	private static final String EXTENSION = ".xsd";

	private final Map<String, byte[]> schemaData;

	public SchemaDefinitionService() {
		this.schemaData = Collections.unmodifiableMap(loadSchemas());
	}

	private static Map<String, byte[]> loadSchemas() {
		var result = new HashMap<String, byte[]>();
		var scanner = new ClassPathScanningCandidateComponentProvider(true);
		scanner.addIncludeFilter(new AnnotationTypeFilter(XmlRootElement.class));
		for (var bean : scanner.findCandidateComponents(RelyingPartySetup.class.getPackageName())) {
			var name = getSchemaName(bean.getBeanClassName());
			var data = loadSchema(name);
			if (data.length > 0) {
				result.put(name, data);
			}
		}
		return result;
	}

	private static String getSchemaName(String className) {
		try {
			var cls = Class.forName(className);
			// the files are named after the class, not the XmlRootElement.name:
			return cls.getSimpleName() + EXTENSION;
		}
		catch (ClassNotFoundException ex) {
			throw new TechnicalException(String.format("Could not find class=%s", className), ex);
		}
	}

	private static byte[] loadSchema(String name) {
		try {
			var schema = XmlConfigController.class.getClassLoader().getResourceAsStream(name);
			if (schema == null) {
				log.debug("schema={} not on classpath", name);
				return new byte[0];
			}
			var data = schema.readAllBytes();
			log.debug("Loaded schema={} ({} bytes)", name, data.length);
			return data;
		}
		catch (IOException ex) {
			log.error(String.format("Could not load schema=%s from classpath", name), ex);
			return new byte[0];
		}
	}

	public byte[] getSchema(String schema) {
		var data = schemaData.get(schema);
		if (data == null) {
			throw new RequestDeniedException(String.format("Invalid schema=%s requested", schema));
		}
		return data;
	}

}
