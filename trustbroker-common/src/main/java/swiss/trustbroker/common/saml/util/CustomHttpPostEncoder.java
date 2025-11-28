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

import java.util.Map;

import org.apache.velocity.VelocityContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;

/**
 * SAML encoder that allows custom parameters for a custom template.
 */
@SuppressWarnings("java:S110") // number of parent classes not under our control
public class CustomHttpPostEncoder<T> extends NonFlushingHttpPostEncoder {

	private final Map<String, T> contextValues;

	public CustomHttpPostEncoder(String velocityTemplateId, Map<String, T> contextValues) {
		super();
		setVelocityTemplateId(velocityTemplateId);
		this.contextValues = contextValues;
	}

	@Override
	protected void populateVelocityContext(final VelocityContext velocityContext,
			final MessageContext messageContext,
			final String endpointURL) throws MessageEncodingException {
		super.populateVelocityContext(velocityContext, messageContext, endpointURL);
		VelocityUtil.populateVelocityContext(velocityContext, contextValues);
	}

}
