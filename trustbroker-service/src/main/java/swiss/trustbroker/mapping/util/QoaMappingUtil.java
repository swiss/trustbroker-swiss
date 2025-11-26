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

package swiss.trustbroker.mapping.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.StandardErrorCode;
import swiss.trustbroker.federation.xmlconfig.AcClass;
import swiss.trustbroker.federation.xmlconfig.Qoa;
import swiss.trustbroker.federation.xmlconfig.QoaComparison;
import swiss.trustbroker.mapping.dto.CustomQoa;
import swiss.trustbroker.mapping.dto.QoaConfig;
import swiss.trustbroker.sessioncache.dto.StateData;

/**
 * Mostly internal helper for QoaMappingService.
 * Otherwise, to be used from static contexts only.
 */
@Slf4j
public class QoaMappingUtil {

	private QoaMappingUtil() {
	}

	/**
	 * @param requestQoaConf config corresponding to expectedContextClasses
	 * @param qoaConfig config corresponding to actualContextClass
	 */
	@SuppressWarnings("java:S107") // large number of parameters as it's used from static context
	public static boolean validateContextClass(
			QoaComparison comparison, List<String> expectedContextClasses, QoaConfig requestQoaConf, // request
			String actualContextClass, QoaConfig qoaConfig, String issuer,// response
			Map<String, Integer> globalMapping, boolean checkOnly) {

		if (CollectionUtils.isEmpty(expectedContextClasses)) {
			log.debug("Missing State expectedCtxClasses issuer={}, skipping AuthnContextClassRef validation", qoaConfig.issuerId());
			return true;
		}

		if (comparison == null) {
			log.debug("Missing Qoa comparison issuer={}, skipping AuthnContextClassRef validation", qoaConfig.issuerId());
			return true;
		}

		if (!StringUtils.hasLength(actualContextClass)) {
			if (!checkOnly) {
				missingQoaException(comparison, expectedContextClasses, qoaConfig, requestQoaConf);
			}
			return false;
		}

		var qoaOrders = getQoaOrders(actualContextClass, qoaConfig, globalMapping, false);
		var contextClassOrders = expectedContextClasses.stream()
				.flatMap(acClass -> getQoaOrders(acClass, requestQoaConf, globalMapping, false).stream())
				.collect(Collectors.toSet());

		var isValid = validateQoaComparison(qoaConfig, comparison, contextClassOrders, qoaOrders);
		if (!isValid && !checkOnly) {
			invalidQoaException(comparison, actualContextClass, expectedContextClasses, qoaConfig, issuer);
		}

		return isValid;
	}

	static boolean validateQoaComparison(QoaConfig cpQoaConf, QoaComparison comparison, Set<Integer> expectedQoaOrders,
			Set<Integer> actualQoas) {

		if (CollectionUtils.isEmpty(expectedQoaOrders)) {
			log.debug("Missing Qoa orders cpIssuer={}, skipping comparison validation", cpQoaConf.issuerId());
			return true;
		}

		var qoaMin = Collections.min(expectedQoaOrders);
		var qoaMax = Collections.max(expectedQoaOrders);

		return (comparison != null) && switch (comparison) {
			// the resulting authentication context in the authentication statement MUST be the exact match of
			// at least one of the authentication contexts specified.
			case EXACT -> expectedQoaOrders.stream().anyMatch(actualQoas::contains);
			// the resulting authentication context in the authentication statement MUST be at least as
			// strong (as deemed by the responder) as one of the authentication contexts specified.
			case MINIMUM -> actualQoas.stream().anyMatch(actualQoa -> actualQoa >= qoaMin);
			//  the resulting authentication context in the authentication statement MUST be as strong as possible
			//  (as deemed by the responder) without exceeding the strength of at least one of the authentication contexts specified.
			case MAXIMUM -> actualQoas.stream().anyMatch(actualQoa -> actualQoa <= qoaMax);
			// the resulting authentication context in the authentication statement MUST be stronger (as deemed by the responder)
			// than any one of the authentication contexts specified.
			case BETTER -> actualQoas.stream().anyMatch(actualQoa -> actualQoa > qoaMin);
		};
	}

	private static void invalidQoaException(QoaComparison comparison, String actualContextClass,
			List<String> expectedContextClasses, QoaConfig qoaConfig, String reqIssuer) {
		invalidQoaException(comparison, List.of(actualContextClass), expectedContextClasses, qoaConfig, reqIssuer);
	}

	static void invalidQoaException(QoaComparison comparison, List<String> actualContextClasses,
			List<String> expectedContextClasses, QoaConfig qoaConfig, String reqIssuer) {
		if (!qoaConfig.hasConfig()) {
			return;
		}

		var msg = String.format(
				"Invalid Qoa in request actualCtxClasses=%s expectedCtxClasses=%s comparison=%s issuer=%s confIssuer=%s ",
				actualContextClasses,expectedContextClasses, comparison, reqIssuer, qoaConfig.issuerId());
		if (enforceQoa(qoaConfig)) {
			throw new RequestDeniedException(StandardErrorCode.NO_AUTHN_CONTEXT, msg);
		}
		else {
			logEnforceWarn(msg);
		}
	}

	private static void logEnforceWarn(String msg) {
		log.warn("Qoa.enforce=false: {}", msg);
	}

	public static boolean enforceQoa(QoaConfig cpQoaConf) {
		return cpQoaConf.hasConfig() && cpQoaConf.config().enforce();
	}

	public static boolean enforceQoa(QoaConfig rpQoaConf, QoaConfig cpQoaConf) {
		var cpEnforce = cpQoaConf.hasConfig() && cpQoaConf.config().enforce();
		var rpEnforce = rpQoaConf.hasConfig() && rpQoaConf.config().enforce();
		return cpEnforce || rpEnforce;
	}

	public static void validateRpContextClasses(QoaConfig configQoa, List<String> requestContextClasses,
			AuthnContextComparisonTypeEnumeration comparison, Map<String, Integer> globalMapping) {

		log.debug("Incoming requestCtxClasses={}, issuer={}", requestContextClasses, configQoa.issuerId());

		if (!configQoa.hasConfig()) {
			log.debug("Missing Qoa config for issuer={} - skipping Qoa validation", configQoa.issuerId());
			return;
		}

		if (comparison == null) {
			log.debug("Missing Qoa Comparison issuer={}", configQoa.issuerId());
		}

		isKnownQoaLevels(requestContextClasses, configQoa, globalMapping, false);
	}

	static void isKnownQoaLevels(List<String> requestContextClasses, QoaConfig configQoa, Map<String, Integer> globalMapping,
			Boolean outbound) {

		for (var contextClass : requestContextClasses) {

			// check if the QOA level is known in Rp or Global config
			var orders = getQoaOrders(contextClass, configQoa, globalMapping, outbound);

			// check config class to determine level
			var configAcClasses = getConfigAcClasses(contextClass, configQoa.config(), outbound);
			// 	Accept QOA with different name but same order
			if (!orders.isEmpty() && configAcClasses.isEmpty()) {
				configAcClasses = getConfigAcClassesByOrders(configQoa, orders, globalMapping, outbound);
			}
			if (configAcClasses.isEmpty() || orders.isEmpty()) {
				invalidQoaException(configQoa, contextClass);
			}
		}
	}

	public static List<AcClass> getConfigAcClassesByOrders(QoaConfig configQoa, Set<Integer> orders,
			Map<String, Integer> globalMapping, Boolean outbound) {
		List<AcClass> result = new ArrayList<>();
		if (orders.isEmpty() || !configQoa.hasConfig()) {
			return result;
		}
		for (var acClass : configQoa.config().getClasses()) {
			if (acClass.applyForDirection(outbound)) {
				var configQoaOrder =
						getAcClassOrder(acClass, configQoa.issuerId(), globalMapping, CustomQoa.UNDEFINED_QOA_ORDER);
				if (orders.contains(configQoaOrder)) {
					result.add(acClass);
				}
			}
			// else: ACClass for one direction only, ignore for the other
		}
		return result;
	}

	private static void invalidQoaException(QoaConfig configQoa, String contextClass) {
		if (!configQoa.hasConfig()) {
			log.debug("Missing qoa configuration for={}, disabled Qoa validation of issuer={}",
					configQoa.issuerId(), contextClass);
			return;
		}
		if (configQoa.config().enforce()) {
			throw new RequestDeniedException(StandardErrorCode.NO_AUTHN_CONTEXT,
					String.format("Missing ctxClass=%s in config (HINT: check application.yaml trustbroker.config.qoa"
							+ " or the SetupRP.xml) for rpIssuer=%s qoaConf=%s", contextClass, configQoa.issuerId(), configQoa));
		}
		else {
			log.warn("Qoa.enforce=false. Missing ctxClass=\"{}\" in config  (HINT: check application.yaml trustbroker.config.qoa"
					+ " or the SetupRP.xml) for rpIssuer=\"{}\" qoaConf=\"{}\"", contextClass, configQoa.issuerId(), configQoa);
		}
	}

	public static void missingQoaException(QoaComparison comparison, List<String> expectedContextClasses,
			QoaConfig cpQoaConf, QoaConfig rpQoaConf) {

		if (!cpQoaConf.hasConfig() && !rpQoaConf.hasConfig()) {
			return;
		}

		var cpEnforce = cpQoaConf.hasConfig() && cpQoaConf.config().enforce();
		var rpEnforce = rpQoaConf.hasConfig() && rpQoaConf.config().enforce();

		var msg = String.format("Missing Qoa in request cpIssuer=%s, expectedCtxClasses=%s comparison=%s rpIssuer=%S",
				cpQoaConf.issuerId(), expectedContextClasses, comparison, rpQoaConf.issuerId());
		if (cpEnforce || rpEnforce) {
			throw new RequestDeniedException(StandardErrorCode.NO_AUTHN_CONTEXT, msg);
		}
		else {
			log.warn(msg);
		}
	}

	static List<AcClass> getConfigAcClasses(String contextClass, Qoa configQoa, Boolean outbound) {
		if (configQoa == null || CollectionUtils.isEmpty(configQoa.getClasses())) {
			return Collections.emptyList();
		}
		List<AcClass> result = new ArrayList<>();
		for (var acClass : configQoa.getClasses()) {
			if (acClass.applyForDirection(outbound) && Objects.equals(acClass.getContextClass(), contextClass)) {
				result.add(acClass);
			}
		}
		return result;
	}

	public static List<String> getQoasByLevels(Set<Integer> levels, Map<String, Integer> globalMapping) {
		List<String> result = new ArrayList<>();
		for (Map.Entry<String, Integer> entry : globalMapping.entrySet()) {
			if (levels.contains(entry.getValue())) {
				result.add(entry.getKey());
			}
		}
		return result;
	}

	public static Integer getMaxQoaOrder(List<String> classRefs, QoaConfig configQoa, Map<String, Integer> globalMapping) {
		if (CollectionUtils.isEmpty(classRefs)) {
			return CustomQoa.UNDEFINED_QOA_ORDER;
		}
		// usually
		var maxQoa = classRefs.stream()
				.flatMap(contextClass -> getQoaOrders(contextClass, configQoa, globalMapping, null).stream())
				.filter(qoaOrder -> qoaOrder >= 0)
				.max(Integer::compareTo)
				.orElse(0);
		log.debug("issuer={} returned contextClasses={} with max qoa={}", configQoa.issuerId(), classRefs, maxQoa);
		return maxQoa;
	}

	public static Integer getNearestMaxQoaOrder(List<String> classRefs, QoaConfig configQoa, Integer qoaMaxOrder, Map<String, Integer> globalMapping) {
		if (CollectionUtils.isEmpty(classRefs)) {
			return CustomQoa.UNDEFINED_QOA_ORDER;
		}
		// usually
		var qoaOrders = classRefs.stream()
							  .flatMap(contextClass -> getQoaOrders(contextClass, configQoa, globalMapping, null).stream())
							  .toList();
		var maxQoa = -1;
		for (var qoaOrder : qoaOrders) {
			if (qoaOrder >= maxQoa && qoaOrder <= qoaMaxOrder) {
				maxQoa = qoaOrder;
			}
		}
		log.debug("issuer={} returned contextClasses={} with max qoa={}", configQoa.issuerId(), classRefs, maxQoa);
		return maxQoa;
	}

	public static Set<Integer> getQoaOrders(String classRef, QoaConfig configQoa, Map<String, Integer> globalMapping,
			Boolean outbound) {
		var configAcClasses = getConfigAcClasses(classRef, configQoa.config(), outbound);
		if (!configAcClasses.isEmpty()) {
			var result = configAcClasses.stream()
				.map(AcClass::getOrder)
				.filter(Objects::nonNull)
				.collect(Collectors.toSet());
			if (!result.isEmpty()) {
				return result;
			}
		}
		var level = globalMapping.get(classRef);
		if (level == null) {
			if (!configQoa.hasConfig()) {
				return Set.of(CustomQoa.UNDEFINED_QOA_ORDER);
			}
			// level must be defined in global or RP config
			var msg = String.format(
					"Missing Qoa in config ctxClass=%s issuer=%s, cannot determine order"
							+ " (HINT: Check trustbroker.config.qoa or SetupRP.xml/SetupCP.xml defining order)",
					classRef, configQoa.issuerId());
			if (configQoa.config().enforce()) {
				throw new RequestDeniedException(StandardErrorCode.NO_AUTHN_CONTEXT, msg);
			}
			else {
				logEnforceWarn(msg);
			}
			return Set.of(CustomQoa.UNDEFINED_QOA_ORDER);
		}
		return Set.of(level);
	}

	public static Set<Integer> getQoaOrders(String classRef, QoaConfig inboundQoaConf, QoaConfig outboundQoaConf, Map<String, Integer> globalMapping) {
		var configAcClasses = getConfigAcClasses(classRef, outboundQoaConf.config(), true);
		if (!configAcClasses.isEmpty()) {
			var result = configAcClasses.stream()
										.map(AcClass::getOrder)
										.filter(Objects::nonNull)
										.collect(Collectors.toSet());
			if (!result.isEmpty()) {
				return result;
			}
		}
		var level = globalMapping.get(classRef);
		// mapped Qoa level was not found in the Rp or Global -> Qoa was not mapped, check if the CP config has the level
		if (level == null) {
			configAcClasses = getConfigAcClasses(classRef, inboundQoaConf.config(), false);
			if (!configAcClasses.isEmpty()) {
				var result = configAcClasses.stream()
											.map(AcClass::getOrder)
											.filter(Objects::nonNull)
											.collect(Collectors.toSet());
				if (!result.isEmpty()) {
					return result;
				}
			}
		}

		if (level == null) {
			// level must be defined in global or RP/CP config
			var msg = String.format(
					"Missing Qoa in config ctxClass=%s inboundIssuer=%s outboundIssuer=%s, cannot determine order"
							+ " (HINT: Check trustbroker.config.qoa or SetupRP.xml/SetupCP.xml defining Qoa model)",
					classRef, inboundQoaConf.issuerId(), outboundQoaConf.issuerId());
			if (inboundQoaConf.config().enforce() || outboundQoaConf.config().enforce()) {
				throw new RequestDeniedException(StandardErrorCode.NO_AUTHN_CONTEXT, msg);
			}
			else {
				logEnforceWarn(msg);
			}
			return Set.of(CustomQoa.UNDEFINED_QOA_ORDER);
		}
		return Set.of(level);
	}

	public static List<String> computeQoasForComparisonType(QoaConfig configQoa, Map<String, Integer> globalMapping,
			List<String> matchContextClasses) {
		if (!configQoa.hasConfig()) {
			return Collections.emptyList();
		}
		var comparison = configQoa.config().getComparison();
		var contextClasses = configQoa.config().getClasses();
		if (comparison == null) {
			comparison = QoaComparison.EXACT;
		}
		return switch (comparison) {
			case EXACT -> getExactQoas(contextClasses, matchContextClasses);
			case MINIMUM, BETTER -> getMinQoa(contextClasses, matchContextClasses, configQoa.issuerId(), globalMapping);
			case MAXIMUM -> getMaxQoa(contextClasses, matchContextClasses, configQoa.issuerId(), globalMapping);
		};
	}

	static List<String> getExactQoas(List<AcClass> contextClasses, List<String> matchContextClasses) {
		return contextClasses.stream()
				.filter(contextClass -> matchContextClass(contextClass, matchContextClasses))
					.map(AcClass::getContextClass)
					.filter(Objects::nonNull)
					.distinct()
					.toList();
	}

	static List<String> getMinQoa(List<AcClass> classes, List<String> matchContextClasses, String issuerId,
								  Map<String, Integer> globalMapping) {
		var minQOa = classes.stream()
				.filter(acClass -> matchContextClass(acClass, matchContextClasses))
				.filter(acClass -> getAcClassOrder(acClass, issuerId, globalMapping, Integer.MAX_VALUE) >= 0)
				.min((acClass1, acClass2) -> compare(acClass1, acClass2, issuerId, globalMapping, Integer.MAX_VALUE));
		return getContextClassList(minQOa);
	}

	static List<String> getMaxQoa(List<AcClass> classes, List<String> matchContextClasses, String issuerId,
			Map<String, Integer> globalMapping) {
		var maxQoa = classes.stream()
				.filter(acClass -> matchContextClass(acClass, matchContextClasses))
				.filter(acClass -> getAcClassOrder(acClass, issuerId, globalMapping, Integer.MAX_VALUE) >= 0)
				.max((acClass1, acClass2) -> compare(acClass1, acClass2, issuerId, globalMapping, Integer.MIN_VALUE));
		return getContextClassList(maxQoa);
	}

	private static List<String> getContextClassList(Optional<AcClass> qoa) {
		if (qoa.isEmpty()) {
			return Collections.emptyList();
		}
		var contextClass = qoa.get().getContextClass();
		if (contextClass == null) {
			log.info("Ignoring null contextClass"); // no context at this point, context/warning should be logged before
			return Collections.emptyList();
		}
		return List.of(contextClass);
	}

	private static boolean matchContextClass(AcClass contextClass, List<String> matchContextClasses) {
		if (matchContextClasses.isEmpty()) {
			return true;
		}
		return matchContextClasses.contains(contextClass.getContextClass());
	}

	private static int compare(AcClass acClass1, AcClass acClass2,
			String issuerId, Map<String, Integer> globalMapping, Integer undefinedOrder) {
		var order1 = getAcClassOrder(acClass1, issuerId, globalMapping, undefinedOrder);
		var order2 = getAcClassOrder(acClass2, issuerId, globalMapping, undefinedOrder);
		return order1.compareTo(order2);
	}

	static Integer getAcClassOrder(AcClass acClass, String issuerId, Map<String, Integer> globalMapping, Integer undefinedOrder) {
		var order = acClass.getOrder();
		if (order == null) {
			order = globalMapping.get(acClass.getContextClass());
		}
		if (order == null || order == CustomQoa.UNDEFINED_QOA_ORDER) {
			order = undefinedOrder;
			log.info("Could not determine Qoa level for issuerId={} contextClass={} using={}",
					issuerId, acClass.getContextClass(), order);
		}
		return order;
	}

	public static Optional<List<String>> getReplacementAcClasses(Qoa qoa) {
		if (qoa != null && qoa.getClasses() != null) {
			List<String> classes = new ArrayList<>();
			for (AcClass acClass : qoa.getClasses()) {
				if (Boolean.TRUE.equals(acClass.getReplaceInbound())) {
					classes.add(acClass.getContextClass());
				}
			}
			return Optional.of(classes);
		}
		return Optional.empty();
	}

	public static void rejectRequestIfQoaConfMissing(Qoa qoaConfig, boolean enforceQoaIfMissing, String issuerId) {
		boolean enforce = (qoaConfig != null && qoaConfig.getEnforce() != null) ? qoaConfig.getEnforce() : enforceQoaIfMissing;
		boolean rejectRequest = enforce && (qoaConfig == null || qoaConfig.getClasses().isEmpty());
		if (rejectRequest) {
			throw new RequestDeniedException(
					String.format("Missing request context class from request or SetupRp configuration with ID=%s", issuerId));
		}
	}

	public static List<String> getDowngradedQoas(List<String> requestQoaList, List<String> mappedQoas, QoaConfig inboundQoaConfig, QoaConfig outboundQoaConfig, Map<String, Integer> globalMapping) {
		List<String> result = new ArrayList<>();
		for (String qoaClass : mappedQoas) {
			// if the Qoa could not be mapped and the order is not in global -> check in the inbound config too
			var outboundQoaOrders = QoaMappingUtil.getQoaOrders(qoaClass, outboundQoaConfig, inboundQoaConfig, globalMapping);
			if (!outboundQoaOrders.isEmpty()) {
				var inboundConfigAcClasses = QoaMappingUtil.getConfigAcClassesByOrders(inboundQoaConfig, outboundQoaOrders, globalMapping, false);
				var downgradedClasses = getDowngradedClasses(outboundQoaConfig, requestQoaList, inboundConfigAcClasses, qoaClass, outboundQoaOrders, globalMapping);
				if (!downgradedClasses.isEmpty()) {
					result.addAll(downgradedClasses);
				}
				else {
					result.add(qoaClass);
				}
			} else {
				log.debug("Could not find order for qoa class={}", qoaClass);
				result.add(qoaClass);
			}
		}
		return result;
	}

	static List<String> getDowngradedClasses(QoaConfig outboundQoaConfig, List<String> requestContextClasses,
											 List<AcClass> inboundConfigAcClasses, String contextClass,
											 Set<Integer> qoaOrders, Map<String, Integer> globalMapping) {
		List<String> result = new ArrayList<>();
		if (requestContextClasses == null || requestContextClasses.isEmpty() || requestContextClasses.contains(contextClass)) {
			return result;
		}
		var qoaMaxOrder = qoaOrders.stream().max(Integer::compareTo).orElse(-1);
		var maxOutboundQoaOrder = getNearestMaxQoaOrder(requestContextClasses, outboundQoaConfig, qoaMaxOrder, globalMapping);

		if (maxOutboundQoaOrder == -1 || qoaMaxOrder == -1) {
			return result;
		}

		// find matching inbound AcClass
		var acClass = inboundConfigAcClasses.stream().filter(accClass -> qoaMaxOrder > -1 &&
				getAcClassOrder(accClass, outboundQoaConfig.issuerId(), globalMapping, -1).equals(qoaMaxOrder)).findFirst();

		if (acClass.isPresent() && Boolean.TRUE.equals(acClass.get().getDowngradeToMaximumRequested()) && maxOutboundQoaOrder < qoaMaxOrder) {
			var qoa = getContextClassByOrder(requestContextClasses, maxOutboundQoaOrder, outboundQoaConfig, globalMapping, true);
			if (qoa.isPresent()) {
				result.add(qoa.get());
				log.debug("Downgrade Qoa={} with order={} to Qoa={} with order={}", contextClass, qoaMaxOrder, qoa.get(), maxOutboundQoaOrder);
			}
		}
		return result;
	}

	private static Optional<String> getContextClassByOrder(List<String> contextClasses, Integer order, QoaConfig config,
														   Map<String, Integer> globalMapping, Boolean outBound) {
		return contextClasses.stream()
							 .filter(contextClass -> {
								 var qoaOrders = getQoaOrders(contextClass, config, globalMapping, outBound);
								 return !qoaOrders.isEmpty() && qoaOrders.contains(order);
							 })
							 .findFirst();
	}

	public static QoaComparison getRpComparison(StateData stateData, Qoa qoa) {
		var stateComparison = getRpComparison(stateData);
		if (stateComparison != null) {
			return stateComparison;
		}
		return qoa != null ? qoa.getComparison() : null;
	}

	public static QoaComparison getRpComparison(StateData stateData) {
		if (stateData == null || stateData.getSpStateData() == null) {
			return null;
		}
		return stateData.getSpStateData().getComparisonType();
	}

	public static List<String> getRpContextClasses(StateData stateData, Qoa qoa) {
		var rpContextClasses = getRpContextClasses(stateData);
		return getRpContextClasses(rpContextClasses, qoa);
	}

	public static List<String> getRpContextClasses(List<String> rpContextClasses, Qoa qoa) {
		if (rpContextClasses != null && !rpContextClasses.isEmpty()) {
			return rpContextClasses;
		}
		return qoa != null && qoa.getClasses() != null ? qoa.getClasses().stream().map(AcClass::getContextClass).toList() : null;
	}

	public static List<String> getRpContextClasses(StateData stateData) {
		List<String> contextClasses = new ArrayList<>();
		if (stateData != null && stateData.getRpContextClasses() != null) {
			contextClasses.addAll(stateData.getRpContextClasses());
		}
		return contextClasses;
	}
}
