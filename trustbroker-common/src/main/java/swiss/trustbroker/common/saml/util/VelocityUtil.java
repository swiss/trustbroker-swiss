/*
 * Derivative work of original class from org.opensaml:opensaml-saml-impl:5.1.2:
 * org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package swiss.trustbroker.common.saml.util;

import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.servlet.HttpServletSupport;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.springframework.http.MediaType;
import swiss.trustbroker.common.exception.ErrorMarker;
import swiss.trustbroker.common.exception.ExceptionUtil;
import swiss.trustbroker.common.exception.TechnicalException;

/**
 * renderTemplate copied from HTTPPostEncoder and adapted.
 */
@Slf4j
public class VelocityUtil {

	public static final String VELOCITY_SLO_TEMPLATE_ID = "/templates/SLO-SAML2-POST.vm";

	public static final String VELOCITY_PARAM_XTB_SIG_ALG = "XTBSigAlg";

	public static final String VELOCITY_PARAM_XTB_SIGNATURE = "XTBSignature";

	public static final String VELOCITY_PARAM_XTB_HTTP_METHOD = "XTBHttpMethod";

	public static final String VELOCITY_PARAM_ACTION = "action"; // from OpenSaml

	private VelocityUtil() {}

	public static <T> void populateVelocityContext(VelocityContext velocityContext, Map<String, T> contextValues) {
		log.debug("Velocity contextValues={}", contextValues);
		for (var entry : contextValues.entrySet()) {
			velocityContext.put(entry.getKey(), entry.getValue());
		}
	}

	public static <T> void renderTemplate(
			VelocityEngine velocityEngine, HttpServletResponse response, String velocityTemplate,
			Map<String, T> contextValues) {
		var context = new VelocityContext();
		populateVelocityContext(context, contextValues);
		renderTemplate(velocityEngine, response, velocityTemplate, context);
	}

	// HTTPPostEncoder.postEncode copied, not flushing the stream to allow TX commit
	// Alternative 1: HttpServletResponseWrapper with custom output catching the flush
	// Alternative 2: Use @Transactional on SamlController split away from AppController
	public static void renderTemplate(
			VelocityEngine velocityEngine, HttpServletResponse response, String velocityTemplate,
			VelocityContext context) {
		log.debug("Rendering velocityTemplate={}", velocityTemplate);
		try {
			HttpServletSupport.addNoCacheHeaders(response);
			HttpServletSupport.setUTF8Encoding(response);
			HttpServletSupport.setContentType(response, MediaType.TEXT_HTML.toString());

			try (var out = new OutputStreamWriter(response.getOutputStream(), StandardCharsets.UTF_8)) {
				velocityEngine.mergeTemplate(velocityTemplate, StandardCharsets.UTF_8.name(), context, out);
				// Not out.flush the stream so spring-mvc transactional aspect can kick in first
			}
		}
		catch (Exception ex) {
			if (ExceptionUtil.isClientDisconnected(ex)) {
				throw new TechnicalException(ErrorMarker.CLIENT_DISCONNECT, String.format(
						"Connection to client broken while rendering Velocity template msg='%s'", ex.getMessage()), ex);
			}
			throw new TechnicalException(
					String.format("Error rendering Velocity template msg='%s'", ex.getMessage()), ex);
		}
	}

}
