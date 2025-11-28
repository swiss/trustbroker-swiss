/*
 * Copyright (C) 2024 trustbroker.swiss team BIT
 */

package swiss.trustbroker.federation.xmlconfig;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * This class describes the configuration of the provisioning for a CP.
 *
 * @since 1.12.0
 * @see swiss.trustbroker.api.idm.service.IdmProvisioningService
 */
@XmlRootElement(name = "Provisioning")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Provisioning implements Serializable {

	/**
	 * Enable IDM provisioning based on CP response.
	 * <br/>
	 * Default: FALSE
	 */
	@XmlAttribute(name = "enabled")
	private ProvisioningMode enabled;

	/**
	 * Provisioning mode flags passed to the implementations.
	 */
	@XmlElement(name = "Mode")
	@Builder.Default
	private List<String> modes = new ArrayList<>();

	public ProvisioningMode getProvisioning() {
		return enabled != null ? enabled : ProvisioningMode.FALSE;
	}
}
