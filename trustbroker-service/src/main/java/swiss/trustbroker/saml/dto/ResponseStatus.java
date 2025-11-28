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

package swiss.trustbroker.saml.dto;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.config.dto.SamlProperties;
import swiss.trustbroker.federation.xmlconfig.Flow;
import swiss.trustbroker.saml.util.SamlStatusCode;

/**
 * Base class for CP and RP side status codes.
 */
@Data
@Slf4j
@SuperBuilder(toBuilder = true)
@NoArgsConstructor
public abstract class ResponseStatus implements Serializable {

	/**
	 * Usually urn:oasis:names:tc:SAML:2.0:status:Responder
	 */
	protected String statusCode;

	/**
	 * E.g. urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile
	 */
	protected String statusNestedCode;

	/**
	 * E.g. SAML Federation not completed due to ....
	 */
	protected String statusMessage;

	/**
	 * Optional flow policy to control the abort flow.
	 */
	protected Flow flowPolicy;

	/**
	 * Set by scripts to toggle features, to be consumed by the respective implementations.
	 * <br/>
	 * Potentially breaking changes:
	 * <ul>
	 *     <li>With 1.11.0 This changed from <code>Set</code> to <code>Map</code>. Scripts that access the getter/setter
	 *     directly have to be adapted (use <code>featureConditionSet</code>, <code>featureConditions</code>).</li>
	 * </ul>
	 *
	 * @since 1.9.0
	 */
	@Builder.Default
	private Map<String, String> featureConditions = new HashMap<>();

	// Error handling: Script might abort the federation with a message to RP

	/**
	 * Abort a SAML exchange (script hook).
	 */
	public void abort(String statusCode, String statusMessage, String statusNestedCode) {
		abort(statusCode, statusMessage, statusNestedCode, null);
	}

	/**
	 * Abort a SAML exchange with a message to RP.
	 */
	public void abort(String statusCode, Flow flowPolicy) {
		abort(statusCode, null, null, flowPolicy);
	}

	/**
	 * Abort a SAML exchange with a message to RP.
	 */
	public void abort(String statusCode, String statusMessage, String statusNestedCode, Flow flowPolicy) {
		log.info("Abort request for statusCode={} statusMessage=\"{}\", statusNestedCode={}, flowPolicy={}",
				statusCode, statusMessage, statusNestedCode, flowPolicy);
		this.statusCode = statusCode;
		this.statusMessage = statusMessage;
		this.statusNestedCode = statusNestedCode;
		this.flowPolicy = flowPolicy;
	}

	/**
	 * Reset error page passed as flow policy to abort.
	 */
	public void resetErrorPageStatus() {
		if (showErrorPage()) {
			log.info("Clearing flow policy for statusCode={} statusMessage=\"{}\", statusNestedCode={}, flowPolicy={}",
					statusCode, statusMessage, statusNestedCode, flowPolicy);
			flowPolicy = Flow.builder()
							 .id(flowPolicy.getId())
							 .namespacePrefix(flowPolicy.getNamespacePrefix())
							 .build();
		}
	}

	public void copyAbortConditions(ResponseStatus responseStatus) {
		this.statusCode = responseStatus.getStatusCode();
		this.statusMessage = responseStatus.getStatusMessage();
		this.statusNestedCode = responseStatus.getStatusNestedCode();
		this.flowPolicy = responseStatus.getFlowPolicy();
	}

	@JsonIgnore // bean method
	public boolean isAborted() {
		return this.statusCode != null;
	}

	public boolean showErrorPage() {
		return isAborted() && flowPolicy != null && flowPolicy.showErrorPage();
	}

	public boolean doAppRedirect() {
		return flowPolicy != null && flowPolicy.doAppRedirect();
	}

	public String statusMessage() {
		return statusMessage(null);
	}

	public String statusMessage(SamlProperties samlProperties) {
		if (statusMessage != null) {
			return statusMessage;
		}
		return getSamlCode(samlProperties);
	}

	public String nestedStatusCode() {
		return nestedStatusCode(null);
	}

	public String nestedStatusCode(SamlProperties samlProperties) {
		if (statusNestedCode != null) {
			return statusNestedCode;
		}
		return getSamlCode(samlProperties);
	}

	private String getSamlCode(SamlProperties samlProperties) {
		if (flowPolicy == null) {
			return null;
		}
		return SamlStatusCode.addNamespace(samlProperties, flowPolicy.getId(), flowPolicy.getNamespacePrefix());
	}

	public String uiErrorCode() {
		return flowPolicy != null ? SamlStatusCode.toUiErrorCode(flowPolicy.getId()) : null;
	}

	public List<String> uiFlags() {
		return flowPolicy != null ? flowPolicy.uiFlags() : Collections.emptyList();
	}

	/**
	 * Script hook: Toggle features via conditions.
	 *
	 * @since 1.9.0
	 */
	public void featureConditions(Set<String> featureConditions) {
		if (featureConditions == null) {
			reInitializeFeatureConditions();
		}
		else {
			// make sure it is modifiable
			reInitializeFeatureConditions();
			featureConditions.forEach(featureCondition -> this.featureConditions.put(featureCondition, null));
		}
		log.debug("FeatureConditions={} set without parameters", this.featureConditions);

	}

	/**
	 * Script hook: Toggle features via conditions.
	 *
	 * @since 1.11.0
	 */
	public void featureConditions(Map<String, String> featureConditions) {
		if (featureConditions == null) {
			reInitializeFeatureConditions();
		}
		else {
			// make sure it is modifiable
			reInitializeFeatureConditions();
			this.featureConditions.putAll(featureConditions);
		}
		log.debug("FeatureConditions={} set with parameters", this.featureConditions);
	}

	private Map<String, String> initializedFeatureConditions() {
		if (featureConditions == null) {
			reInitializeFeatureConditions();
		}
		return featureConditions;
	}

	private void reInitializeFeatureConditions() {
		featureConditions = new HashMap<>();
	}

	/**
	 * Script hook: Add single feature condition.
	 * @return true if it was not present before
	 * @since 1.9.0
	 */
	public boolean addFeatureCondition(String featureCondition) {
		return addFeatureCondition(featureCondition, null);
	}

	/**
	 * Script hook: Add single feature condition with a nullable parameter.
	 * @return true if it was not present before
	 * @since 1.11.0
	 */
	public boolean addFeatureCondition(String featureCondition, String parameter) {
		if (featureCondition != null) {
			var exists = hasFeatureCondition(featureCondition);
			var previous = initializedFeatureConditions().put(featureCondition, parameter);
			if (!(exists && Objects.equals(previous, parameter))) {
				log.debug("FeatureCondition={} set with parameter={}", featureCondition, parameter);
				return true;
			}
		}
		return false;
	}

	/**
	 * Script hook: Remove single feature condition.
	 * @return true if it was present
	 * @since 1.9.0
	 */
	public boolean removeFeatureCondition(String featureCondition) {
		if ((featureCondition != null) && (featureConditions != null) && featureConditions.containsKey(featureCondition)) {
			featureConditions.remove(featureCondition);
			log.debug("FeatureCondition={} cleared", featureCondition);
			return true;
		}
		return false;
	}

	/**
	 * Script hook: Test single feature condition.
	 *
	 * @since 1.9.0
	 */
	public boolean hasFeatureCondition(String featureCondition) {
		if ((featureCondition != null) && (featureConditions != null) && featureConditions.containsKey(featureCondition)) {
			log.debug("FeatureCondition={} is present", featureCondition);
			return true;
		}
		return false;
	}

	/**
	 * Script hook: Get single feature condition parameter.
	 *
	 * @since 1.11.0
	 */
	public String featureCondition(String featureCondition) {
		if ((featureCondition != null) && (featureConditions != null) && featureConditions.containsKey(featureCondition)) {
			var parameter =  featureConditions.get(featureCondition);
			log.debug("FeatureCondition={} is present with parameter={}", featureCondition, parameter);
			return parameter;
		}
		return null;
	}

	/**
	 * Get all feature conditions.
	 *
	 * @since 1.11.0
	 */
	public Map<String, String> featureConditions() {
		if (featureConditions == null) {
			return Collections.emptyMap();
		}
		return Collections.unmodifiableMap(featureConditions);
	}

	/**
	 * Get all feature conditions without parameters.
	 *
	 * @since 1.11.0
	 */
	public Set<String> featureConditionSet() {
		if (featureConditions == null) {
			return Collections.emptySet();
		}
		return Collections.unmodifiableSet(featureConditions.keySet());
	}
}
