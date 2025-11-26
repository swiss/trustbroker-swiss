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

import org.apache.velocity.VelocityContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;

/**
 * SAML encoder that does not flush the response stream.
 */
@SuppressWarnings("java:S110")
public class NonFlushingHttpPostEncoder extends HTTPPostEncoder {

	public NonFlushingHttpPostEncoder() {
		super();
	}

	@Override
	protected void postEncode(final MessageContext messageContext, final String endpointUrl) throws MessageEncodingException {
		var context = new VelocityContext();
		populateVelocityContext(context, messageContext, endpointUrl);
		VelocityUtil.renderTemplate(getVelocityEngine(), getHttpServletResponse(), getVelocityTemplateId(), context);
	}

}
