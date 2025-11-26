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

package swiss.trustbroker.wstrust.exception;

import javax.xml.namespace.QName;

import lombok.AllArgsConstructor;
import org.springframework.ws.soap.SoapFault;
import org.springframework.ws.soap.SoapFaultDetail;
import org.springframework.ws.soap.server.endpoint.SoapFaultMappingExceptionResolver;
import swiss.trustbroker.exception.GlobalExceptionHandler;

@AllArgsConstructor
public class DetailSoapFaultDefinitionExceptionResolver extends SoapFaultMappingExceptionResolver {

	private static final QName CODE = new QName("code");

	private static final QName DESCRIPTION = new QName("description");

	private final GlobalExceptionHandler globalExceptionHandler;

	@Override
	protected void customizeFault(Object endpoint, Exception ex, SoapFault fault) {
		globalExceptionHandler.logException(ex);
		if (ex instanceof ServiceFaultException sfex) {
			ServiceFault serviceFault = sfex.getServiceFault();
			SoapFaultDetail detail = fault.addFaultDetail();
			detail.addFaultDetailElement(CODE).addText(serviceFault.getCode());
			detail.addFaultDetailElement(DESCRIPTION).addText(serviceFault.getDescription());
		}
	}

}
