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


package swiss.trustbroker.mapping.service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.AcClass;
import swiss.trustbroker.federation.xmlconfig.Qoa;
import swiss.trustbroker.federation.xmlconfig.QoaComparison;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.mapping.dto.CustomQoa;
import swiss.trustbroker.mapping.dto.QoaConfig;
import swiss.trustbroker.mapping.dto.QoaSpec;
import swiss.trustbroker.mapping.util.QoaMappingUtil;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.util.WebSupport;

/**
 * Service for mapping and handling Qoa values from/to RP and CP.
 */
@Service
@AllArgsConstructor
@Slf4j
public class QoaMappingService {

	private final TrustBrokerProperties trustBrokerProperties;

	private final RelyingPartyDefinitions relyingPartiesMapping;

	public CustomQoa extractQoaLevel(String qoa, QoaConfig qoaConfig) {
		if (qoa == null || CustomQoa.UNDEFINED_QOA.getName().equals(qoa)) {
			return CustomQoa.UNDEFINED_QOA;
		}
		var qoaOrders = QoaMappingUtil.getQoaOrders(qoa, qoaConfig, trustBrokerProperties.getQoaMap(), null);

		if (!qoaOrders.isEmpty()) {
			return customQoaFromMaxOrder(qoa, qoaOrders);
		}

		log.error("Could not determine Qoa level for '{}'", qoa);
		return CustomQoa.UNDEFINED_QOA;
	}

	private static CustomQoa customQoaFromMaxOrder(String qoa, Set<Integer> qoaOrders) {
		return new CustomQoa(qoa, qoaOrders.stream()
				.max(Comparator.naturalOrder())
				.orElse(CustomQoa.UNDEFINED_QOA_ORDER));
	}

	public List<CustomQoa> extractQoaLevels(List<String> qoas, QoaConfig qoaConfig) {
		List<CustomQoa> result = new ArrayList<>();
		if (CollectionUtils.isEmpty(qoas)) {
			return List.of(CustomQoa.UNDEFINED_QOA);
		}
		for (var qoa : qoas) {
			result.add(extractQoaLevel(qoa, qoaConfig));
		}

		return result;
	}

	public boolean isStrongestPossible(String name) {
		return trustBrokerProperties.getQoa().getStrongestPossible().equals(name);
	}

	public CustomQoa extractQoaLevelFromAuthLevel(String authLevel, QoaConfig qoaConfig) {
		if (authLevel == null) {
			return CustomQoa.UNDEFINED_QOA;
		}
		var qoaOrders = QoaMappingUtil.getQoaOrders(authLevel, qoaConfig, trustBrokerProperties.getQoaMap(), null);
		if (!qoaOrders.isEmpty()) {
			return customQoaFromMaxOrder(authLevel, qoaOrders);
		}

		log.error("AuthLevel '{}' not found", authLevel);
		return CustomQoa.UNDEFINED_QOA;
	}

	public CustomQoa getDefaultLevel() {
		String defaultQoa = trustBrokerProperties.getQoa().getDefaultQoa();
		var authLevelItem = trustBrokerProperties.getQoaMap().get(defaultQoa);
		if (authLevelItem != null) {
			return new CustomQoa(defaultQoa, authLevelItem);
		}

		log.error("Default authlevel '{}' not found", defaultQoa);
		return CustomQoa.UNDEFINED_QOA;
	}

	public CustomQoa getUnspecifiedLevel() {
		return CustomQoa.UNDEFINED_QOA;
	}

	public CustomQoa getUnspecifiedAuthLevel() {
		return CustomQoa.UNDEFINED_QOA;
	}

	public Optional<Integer> getMinQoaLevel(List<String> contextClasses, QoaConfig qoaConfig) {
		Map<String, Integer> qoaMap = trustBrokerProperties.getQoaMap();
		if (CollectionUtils.isEmpty(contextClasses) || qoaMap.isEmpty()) {
			return Optional.empty();
		}

		return contextClasses.stream()
				.map(qoa -> extractQoaLevel(qoa, qoaConfig))
				.filter(CustomQoa::isRegular)
				.map(CustomQoa::getOrder)
				.min(Comparator.comparing(Integer::valueOf));
	}

	public Integer getMaxQoaOrder(List<String> classRefs, QoaConfig configQoa) {
		return QoaMappingUtil.getMaxQoaOrder(classRefs, configQoa, trustBrokerProperties.getQoaMap());
	}

	// mapping kicks in if OidcClient.usePepQoa=true (which is default at the time being)
	// In that case it might be better to move the flag to the Qoa element, even thought that's CP input, not RP output.
	public List<String> extractPepQoaFromAuthLevel(String authLevel, QoaConfig qoaConfig, String usePepQoaPolicy) {
		if (usePepQoaPolicy.equalsIgnoreCase(Boolean.TRUE.toString())) {
			return extractPepQoaFromAuthLevel(authLevel, qoaConfig);
		}

		return List.of(authLevel); // only the name is used by the caller
	}

	public List<String> extractPepQoaFromAuthLevel(String authLevel, QoaConfig qoaConfig) {
		Map<String, Integer> qoaMap = trustBrokerProperties.getQoaMap();
		Map<String, Integer> legacyMap = trustBrokerProperties.getQoa().getLegacy();
		var qoaOrders = QoaMappingUtil.getQoaOrders(authLevel, qoaConfig, qoaMap, null);
		var qoas = QoaMappingUtil.getQoasByLevels(qoaOrders, legacyMap);
		if (qoas.isEmpty()) {
			return List.of(authLevel); // only the name is used by the caller
		}

		return qoas.stream().distinct().toList();
	}

	/**
	 * Mapping of CP response QoAs to RP outbound.
	 */
	public List<String> mapResponseQoasToOutbound(
			List<String> responseContextClasses, QoaConfig inboundQoaConfig,
			QoaComparison requestComparisonType, List<String> requestContextClasses, QoaConfig outboundQoaConfig) {
		List<String> matchContextClasses = Collections.emptyList();
		// For picking amongst CP response QoAs, MINIMUM/BETTER and MAXIMUM need to be reverted:
		var outboundComparisonType = requestComparisonType == null ? QoaComparison.EXACT :
			switch (requestComparisonType) {
				case EXACT -> QoaComparison.EXACT;
				case MAXIMUM -> QoaComparison.MINIMUM; // RP requested max -> pick min QoA from CP response
														// even better would be: use max that matches the RP requirement
				case MINIMUM, BETTER -> QoaComparison.MAXIMUM; // RP requested min -> pick max Qoa from CP response
			};
		// restrict RP response to single QoA?
		if (outboundQoaConfig.hasConfig() && outboundQoaConfig.config().useSingleQoaInResponse() &&
				requestComparisonType == QoaComparison.EXACT) {
			log.debug("Using comparison MAXIMUM instead of EXACT matching originalContextClasses={} when calculating outbound "
							+ "classes towards issuerId={} to enforce singleQoaResponse",
					requestContextClasses, outboundQoaConfig.issuerId());
			outboundComparisonType = QoaComparison.MAXIMUM;
			if (!requestContextClasses.isEmpty()) {
				matchContextClasses = requestContextClasses;
			}
		}

		// perform mapping
		List<String> mappedQoas =  mapInboundToOutboundQoas(
				responseContextClasses, inboundQoaConfig,
				outboundComparisonType, outboundQoaConfig, matchContextClasses);
		// no Qoa matching RP request: retry without match filter
		if (mappedQoas.isEmpty() && !matchContextClasses.isEmpty()) {
			matchContextClasses = Collections.emptyList();
			mappedQoas =  mapInboundToOutboundQoas(
					responseContextClasses, inboundQoaConfig,
					outboundComparisonType, outboundQoaConfig, matchContextClasses);
		}

		var globalMapping = trustBrokerProperties.getQoaMap();
		if (!mappedQoas.isEmpty()) {
			mappedQoas = QoaMappingUtil.getDowngradedQoas(requestContextClasses, mappedQoas, inboundQoaConfig, outboundQoaConfig, globalMapping);
		}

		log.debug("Mapped responseContextClasses={} inboundIssuer={} "
						+ " to contextClasses={} outboundComparisonType={} for "
						+ "outboundIssuer={} requestComparisonType={} requestContextClasses={} matchContextClasses={}",
				responseContextClasses, inboundQoaConfig.issuerId(), mappedQoas,
				outboundComparisonType, outboundQoaConfig.issuerId(), requestComparisonType,
				requestContextClasses, matchContextClasses);

		// Don't apply mapping or order validation on default
		if (mappedQoas.isEmpty() && inboundQoaConfig.hasConfig() && inboundQoaConfig.config().getDefaultQoa() != null)  {
			mappedQoas.add(inboundQoaConfig.config().getDefaultQoa());
			log.debug("Mapped responseContextClasses={} set to defaultQoa={} inboundIssuer={} outboundIssuer={} ",
					responseContextClasses, inboundQoaConfig.config().getDefaultQoa(), inboundQoaConfig.issuerId(), inboundQoaConfig.issuerId());
		}

		return mappedQoas;
	}

	List<String> mapInboundToOutboundQoas(
			List<String> inboundContextClasses, QoaConfig inboundQoaConfig,
			QoaComparison outboundComparisonType, QoaConfig outboundQoaConfig, List<String> matchContextClasses) {

		if (CollectionUtils.isEmpty(inboundContextClasses)) {
			return Collections.emptyList();
		}
		if (!outboundQoaConfig.hasConfig() || CollectionUtils.isEmpty(outboundQoaConfig.config().getClasses())) {
			log.debug("Missing outbound Qoa config outboundIssuer={}, skipping Qoa mapping", outboundQoaConfig.issuerId());
			return inboundContextClasses;
		}
		if (!outboundQoaConfig.config().mapOutbound()) {
			log.debug("Qoa config not outbound for outboundIssuer={}, skipping Qoa mapping", outboundQoaConfig.issuerId());
			return inboundContextClasses;
		}

		List<AcClass> mappedQoas = new ArrayList<>();
		List<AcClass> unmappedQoas = new ArrayList<>();
		var globalMapping = trustBrokerProperties.getQoaMap();
		var dropUnmappableQoas = outboundQoaConfig.config().dropUnmappableQoas();
		// map inbound context class to outbound context class
		for (var contextClass : inboundContextClasses) {
			var qoaOrders = QoaMappingUtil.getQoaOrders(contextClass, inboundQoaConfig, globalMapping, false);
			var configAcClasses = QoaMappingUtil.getConfigAcClassesByOrders(outboundQoaConfig, qoaOrders, globalMapping, true);
			if (!configAcClasses.isEmpty()) {
				mappedQoas.addAll(configAcClasses);
			}
			else {
				log.debug("contextClass={} could not be mapped for outboundIssuer={}", contextClass, outboundQoaConfig.issuerId());
				for (var qoaOrder : qoaOrders) {
					unmappedQoas.add(AcClass.builder().contextClass(contextClass).order(qoaOrder).build());
				}
			}
		}

		// drop only if dropUnmappable=true and there is at least one mappable Qoa
		if (!dropUnmappableQoas || mappedQoas.isEmpty()) {
			mappedQoas.addAll(unmappedQoas);
		}

		var configQoa = new QoaConfig(Qoa.builder()
										 .comparison(outboundComparisonType)
										 .classes(mappedQoas)
										 .build(), outboundQoaConfig.issuerId());
		return QoaMappingUtil.computeQoasForComparisonType(configQoa, trustBrokerProperties.getQoaMap(), matchContextClasses);
	}

	/**
	 * @return default QoAs for config.
	 */
	public List<String> computeDefaultQoaFromConf(QoaConfig qoaConfig) {
		return QoaMappingUtil.computeQoasForComparisonType(qoaConfig, trustBrokerProperties.getQoaMap(), Collections.emptyList());
	}

	/**
	 * Map RP request context classes to outbound CP request.
	 */
	public QoaSpec mapRequestQoasToOutbound(QoaComparison requestComparisonType, List<String> requestContextClasses,
			QoaConfig inboundQoaConfig, QoaConfig outboundQoaConfig) {
		var outboundComparisonType = determineComparisonTypeWithDefault(requestComparisonType, outboundQoaConfig.config());

		if (CollectionUtils.isEmpty(requestContextClasses) &&
				(!inboundQoaConfig.hasConfig() || CollectionUtils.isEmpty(inboundQoaConfig.config().getClasses()))) {
			return new QoaSpec(outboundComparisonType, Collections.emptyList());
		}
		List<String> contextClassesWithDefault =
				determineRequestQoasWithDefault(requestContextClasses, inboundQoaConfig);
		List<String> outboundContextClasses = mapInboundToOutboundQoas(contextClassesWithDefault, inboundQoaConfig,
				outboundComparisonType, outboundQoaConfig, Collections.emptyList());

		log.debug("Mapped requestContextClasses={} requestComparisonType={} inboundIssuer={} to "
						+ "outboundContextClasses={} outboundComparisonType={} for outboundIssuer={}",
				requestContextClasses, requestComparisonType, inboundQoaConfig.issuerId(),
				outboundContextClasses, outboundComparisonType, outboundQoaConfig.issuerId());
		return new QoaSpec(outboundComparisonType, outboundContextClasses);
	}

	/**
	 * @return true if the QOA values defined for the CP allow fulfilling the requested context classes / comparison type,
	 * false if not. Returns true if the CP config has no QOAs defined (CP might return anything),
	 * if the RP did not request QOAs and the RP config does not define defaults (we accept anything),
	 * or if QOA checks are not enforced for either RP or CP (just log the result of the check).
	 */
	public boolean canCpFulfillRequestQoas(QoaComparison requestComparisonType, List<String> requestContextClasses,
			QoaConfig rpQoaConfig, QoaConfig cpQoaConfig) {
		if (CollectionUtils.isEmpty(requestContextClasses) &&
				(!rpQoaConfig.hasConfig() || CollectionUtils.isEmpty(rpQoaConfig.config().getClasses()))) {
			// nothing requested / no defaults
			return true;
		}
		if (!cpQoaConfig.hasConfig() || CollectionUtils.isEmpty(cpQoaConfig.config().getClasses())) {
			// nothing specified for CP
			return true;
		}
		var comparisonType = determineComparisonTypeWithDefault(requestComparisonType, rpQoaConfig.config());
		var rpContextClasses = QoaMappingUtil.getRpContextClasses(requestContextClasses, rpQoaConfig.config());
		var result = cpQoaConfig.config().getClasses()
				.stream()
				.map(AcClass::getContextClass)
				.anyMatch(contextClass ->
						QoaMappingUtil.validateContextClass(
								comparisonType, rpContextClasses, rpQoaConfig,
								contextClass, cpQoaConfig,
								rpQoaConfig.issuerId(), trustBrokerProperties.getQoaMap(), true)
				);
		if (result) {
			log.debug("cpIssuerId={} can fulfill request comparisonType={} contextClasses={}",
					cpQoaConfig.issuerId(), requestComparisonType, rpContextClasses);
			return true;
		}
		var enforce = QoaMappingUtil.enforceQoa(rpQoaConfig, cpQoaConfig);
		log.info("cpIssuerId={} cannot fulfill enforced={} request comparisonType={} contextClasses={}",
				cpQoaConfig.issuerId(), enforce, requestComparisonType, rpContextClasses);
		return !enforce; // allow CP if not enforced
	}

	List<String> determineRequestQoasWithDefault(List<String> requestContextClasses, QoaConfig qoaConfig) {
		if (CollectionUtils.isEmpty(requestContextClasses)) {
			if (qoaConfig.hasConfig() && !CollectionUtils.isEmpty(qoaConfig.config().getClasses())) {
				return computeDefaultQoaFromConf(qoaConfig);
			}
			else {
				return Collections.emptyList();
			}
		}
		return requestContextClasses;
	}

	static QoaComparison determineComparisonTypeWithDefault(QoaComparison comparisonType, Qoa qoaConfig) {
		// override with config
		if (qoaConfig != null && qoaConfig.getComparison() != null) {
			comparisonType = qoaConfig.getComparison();
		}
		// default
		if (comparisonType == null) {
			comparisonType = QoaComparison.EXACT; // default according to SAML2, explicit on CP side
		}
		return comparisonType;
	}

	public QoaConfig getQoaConfiguration(StateData spStateData, RelyingParty relyingParty) {
		if (spStateData != null && spStateData.getOidcClientId() != null) {
			var oidcQoa = getOidcQoa(spStateData.getOidcClientId());
			if (oidcQoa != null) return oidcQoa;
		}
		return relyingParty.getQoaConfig();
	}

	private QoaConfig getOidcQoa(String clientId) {
		var oidcClientConfigById =
				relyingPartiesMapping.getOidcClientConfigById(clientId, trustBrokerProperties);
		if (oidcClientConfigById.isPresent()) {
			var oidcQoa = oidcClientConfigById.get().getQoaConfig();
			if (oidcQoa.hasConfig()) {
				return oidcQoa;
			}
		}
		return null;
	}

	public Qoa getQoaConfiguration(String providerName, String referer, RelyingParty relyingParty) {
		if (WebSupport.isInternalOidcRequest(trustBrokerProperties, referer) && providerName != null) {
			var oidcQoa = getOidcQoa(providerName);
			if (oidcQoa != null) return oidcQoa.config();
		}
		return relyingParty.getQoa();
	}
}
