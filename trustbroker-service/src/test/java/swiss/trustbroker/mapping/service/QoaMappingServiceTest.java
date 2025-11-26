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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.util.SamlContextClass;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.QualityOfAuthenticationConfig;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.AcClass;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.Qoa;
import swiss.trustbroker.federation.xmlconfig.QoaComparison;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.mapping.dto.CustomQoa;
import swiss.trustbroker.mapping.dto.QoaConfig;
import swiss.trustbroker.mapping.dto.QoaSpec;
import swiss.trustbroker.mapping.util.QoaMappingUtil;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.test.saml.util.SamlTestBase;

@SpringBootTest(classes = {QoaMappingService.class})
class QoaMappingServiceTest {

	private static final String RP_ID = "rp1";

	private static final String RP_QOA_10 = "rpQoa10";

	private static final String RP_QOA_20 = "rpQoa20";

	private static final String CP_ID = "cp1";

	private static final String CP_QOA_10 = "cpQoa10";

	private static final String CP_QOA_20 = "cpQoa20";

	private static final String DEFAULT_QOA_70 = SamlTestBase.Qoa.CONTEXT_CLASS_PREFIX + 70;

	@Autowired
	private QoaMappingService qoaMappingService;

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@MockitoBean
	private RelyingPartyDefinitions relyingPartiesMapping;

	@Test
	void extractQoaLevel() {
		mockGlobalQoaMap();
		var qoa = givenQoaConfig(false);
		var qoaConfig = new QoaConfig(qoa, "testId");
		assertThat(qoaMappingService.extractQoaLevel("ANY" + 70, qoaConfig).getOrder(), is(70));
		assertThat(qoaMappingService.extractQoaLevel(null, qoaConfig).getOrder(),
				Matchers.is(SamlTestBase.Qoa.UNSPECIFIED_LEVEL));
		qoaConfig.config().setEnforce(true);
		assertThrows(RequestDeniedException.class, () -> qoaMappingService.extractQoaLevel("bar", qoaConfig));
		assertThat(qoaMappingService.extractQoaLevel(SamlTestBase.Qoa.UNSPECIFIED.getName(), qoaConfig).getOrder(),
				Matchers.is(SamlTestBase.Qoa.UNSPECIFIED_LEVEL));
		assertThat(qoaMappingService.extractQoaLevel(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName(), qoaConfig).getOrder(),
				Matchers.is(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getLevel()));
	}

	@Test
	void extractQoaLevelFromAuthLevel() {
		mockGlobalQoaMap();
		var qoa = givenQoaConfig(false);
		var qoaConfig = new QoaConfig(qoa, "testId");
		assertThat(qoaMappingService.extractQoaLevelFromAuthLevel(SamlContextClass.SOFTWARE_TIME_SYNC_TOKEN, qoaConfig).getOrder(),
				is(30));
		assertThat(qoaMappingService.extractQoaLevelFromAuthLevel(null, qoaConfig).getOrder(),
				Matchers.is(SamlTestBase.Qoa.UNSPECIFIED_LEVEL));
		qoa.setEnforce(true);
		assertThrows(RequestDeniedException.class, () -> qoaMappingService.extractQoaLevelFromAuthLevel("whatever", qoaConfig));
	}

	@Test
	void isRegular() {
		assertThat(new CustomQoa(SamlTestBase.Qoa.STRONGEST_POSSIBLE.getName(),
				CustomQoa.UNDEFINED_QOA.getOrder()).isRegular(), is(false));
		assertThat(new CustomQoa(SamlTestBase.Qoa.UNSPECIFIED.name(),
				SamlTestBase.Qoa.UNSPECIFIED.getLevel()).isRegular(), is(false));
		assertThat(new CustomQoa("10", 10).isRegular(), is(true));
	}

	@Test
	void isStrongestPossible() {
		var qoaMap = givenGlobalQoa();
		when(trustBrokerProperties.getQoa()).thenReturn(qoaMap);
		assertThat(qoaMappingService.isStrongestPossible(SamlTestBase.Qoa.STRONGEST_POSSIBLE.getName()), is(true));
		assertThat(qoaMappingService.isStrongestPossible(SamlTestBase.Qoa.UNSPECIFIED.getName()), is(false));
	}

	@Test
	void mapInboundToOutboundQoasTest() {
		List<String> contextClasses = List.of("class1", "class2", "class3");
		var inboundQoa = Qoa.builder().enforce(true).build();
		var inboundQoaConf = new QoaConfig(inboundQoa, "inbound1");
		Map<String, Integer> globalMapping = Map.of("class1", 1, "class2", 2, "class3", 3);
		when(trustBrokerProperties.getQoaMap()).thenReturn(globalMapping);
		var outboundIssuer = "outbound1";

		assertEquals(contextClasses, qoaMappingService.mapInboundToOutboundQoas(
						contextClasses, inboundQoaConf, QoaComparison.EXACT, new QoaConfig(null, outboundIssuer),
						Collections.emptyList()),
				"Should return the original context classes if outbound config is null.");

		assertEquals(contextClasses, qoaMappingService.mapInboundToOutboundQoas(
						contextClasses, inboundQoaConf, QoaComparison.EXACT, new QoaConfig(Qoa.builder().build(), outboundIssuer),
						Collections.emptyList()),
				"Should return the original context classes if outbound classes are empty.");

		var outBoundQoa1 = Qoa.builder()
							  .mapOutbound(false)
							  .classes(List.of(
									  AcClass.builder().order(1).contextClass("test").build()))
							  .build();
		assertEquals(contextClasses, qoaMappingService.mapInboundToOutboundQoas(
						contextClasses, inboundQoaConf, QoaComparison.EXACT, new QoaConfig(outBoundQoa1, outboundIssuer),
						Collections.emptyList()),
				"Should return the original context classes if MapOutBound is false.");

		var mappedClass1 = "mappedClass1";
		var mappedClass2 = "mappedClass2";
		var mappedClass3 = "mappedClass3";
		var outBoundQoa = Qoa.builder()
							 .enforce(true)
							 .mapOutbound(true)
							 .singleQoaResponse(true) // ignored
							 .classes(List.of(
									 AcClass.builder().order(1).contextClass(mappedClass1).build(),
									 AcClass.builder().order(2).contextClass(mappedClass2).build(),
									 AcClass.builder().order(3).contextClass(mappedClass3).build()))
							 .build();
		var outBoundQoaConf = new QoaConfig(outBoundQoa, outboundIssuer);
		List<String> result = qoaMappingService.mapInboundToOutboundQoas(
				contextClasses, inboundQoaConf, QoaComparison.EXACT, outBoundQoaConf, Collections.emptyList());
		assertEquals(List.of(mappedClass1, mappedClass2, mappedClass3), result, "Should map context classes correctly.");

		result = qoaMappingService.mapInboundToOutboundQoas(
				contextClasses, inboundQoaConf, QoaComparison.EXACT, outBoundQoaConf, Collections.emptyList());
		assertEquals(List.of(mappedClass1, mappedClass2, mappedClass3), result, "Should map context classes correctly.");

		result = qoaMappingService.mapInboundToOutboundQoas(
				contextClasses, inboundQoaConf, QoaComparison.EXACT, outBoundQoaConf, List.of(mappedClass1, mappedClass2));
		assertEquals(List.of(mappedClass1, mappedClass2), result, "Should restrict exact to inbound classes");

		result = qoaMappingService.mapInboundToOutboundQoas(
				contextClasses, inboundQoaConf, QoaComparison.MINIMUM, outBoundQoaConf, Collections.emptyList());
		assertEquals(List.of(mappedClass1), result, "Should map minimum context classes correctly.");

		result = qoaMappingService.mapInboundToOutboundQoas(
				contextClasses, inboundQoaConf, QoaComparison.MINIMUM, outBoundQoaConf, List.of(mappedClass2, mappedClass3));
		assertEquals(List.of(mappedClass2), result, "Should restrict minimum to inbound classes");

		result = qoaMappingService.mapInboundToOutboundQoas(
				contextClasses, inboundQoaConf, QoaComparison.BETTER, outBoundQoaConf, Collections.emptyList());
		assertEquals(List.of(mappedClass1), result, "Should map better context classes correctly.");

		result = qoaMappingService.mapInboundToOutboundQoas(
				contextClasses, inboundQoaConf, QoaComparison.MAXIMUM, outBoundQoaConf, Collections.emptyList());
		assertEquals(List.of(mappedClass3), result, "Should map maximum context classes correctly.");

		result = qoaMappingService.mapInboundToOutboundQoas(
				contextClasses, inboundQoaConf, QoaComparison.MAXIMUM, outBoundQoaConf, List.of(mappedClass1, mappedClass2));
		assertEquals(List.of(mappedClass2), result, "Should restrict maximum to inbound classes");

		outBoundQoaConf.config().setEnforce(false);
		assertEquals(List.of(mappedClass1, mappedClass2, mappedClass3),
				qoaMappingService.mapInboundToOutboundQoas(
						contextClasses, inboundQoaConf, QoaComparison.EXACT, outBoundQoaConf, Collections.emptyList()),
				"Should map context classes correctly.");

		outBoundQoaConf.config().setMapOutbound(false);
		assertEquals(contextClasses, qoaMappingService.mapInboundToOutboundQoas(
						contextClasses, inboundQoaConf, QoaComparison.EXACT, outBoundQoaConf, Collections.emptyList()),
				"Should return original context classes if enforce is false.");
	}

	@Test
	void mapInboundToOutboundQoasDropUnmappableTest() {
		List<String> contextClasses = List.of("class1", "class2", "class3");
		var inboundQoa = Qoa.builder().enforce(true).build();
		var inboundQoaConf = new QoaConfig(inboundQoa, "inbound1");
		var mappedClass1 = "mappedClass1";
		var mappedClass2 = "mappedClass2";
		var outBoundQoa = Qoa.builder()
							 .enforce(true)
							 .mapOutbound(true)
							 .singleQoaResponse(true) // ignored
							 .classes(List.of(
									 AcClass.builder().order(1).contextClass(mappedClass1).build(),
									 AcClass.builder().order(2).contextClass(mappedClass2).build()))
							 .build();
		var outBoundQoaConf = new QoaConfig(outBoundQoa, "outboundIssuer");
		Map<String, Integer> globalMapping = Map.of("class1", 1, "class2", 2, "class3", 3);
		when(trustBrokerProperties.getQoaMap()).thenReturn(globalMapping);

		var result = qoaMappingService.mapInboundToOutboundQoas(
				contextClasses, inboundQoaConf, QoaComparison.EXACT, outBoundQoaConf, Collections.emptyList());
		assertEquals(List.of(mappedClass1, mappedClass2, "class3"), result, "Should keep unmappable context classes.");

		outBoundQoaConf.config().setDropUnmappable(true);
		result = qoaMappingService.mapInboundToOutboundQoas(
				contextClasses, inboundQoaConf, QoaComparison.EXACT, outBoundQoaConf, Collections.emptyList());
		assertEquals(List.of(mappedClass1, mappedClass2), result, "Should drop unmappable context classes.");
	}

	@Test
	void determineRequestQoasWithDefaultTest() {
		assertThat(qoaMappingService.determineRequestQoasWithDefault(null, new QoaConfig(null, null)), is(empty()));
		assertThat(qoaMappingService.determineRequestQoasWithDefault(Collections.emptyList(), new QoaConfig(null, null)), is(empty()));

		var qoa = new Qoa();
		var qoaConfig = new QoaConfig(qoa, "isssuer1");
		qoa.setClasses(new ArrayList<>());
		assertThat(qoaMappingService.determineRequestQoasWithDefault(Collections.emptyList(), qoaConfig), is(empty()));

		qoa.getClasses().add(AcClass.builder().contextClass("rpQoa").build());
		List<String> rpQoaList = qoaMappingService.determineRequestQoasWithDefault(Collections.emptyList(), qoaConfig);
		assertThat(rpQoaList, is(List.of("rpQoa")));

		qoa.getClasses().add(AcClass.builder().contextClass(RP_QOA_10).order(10).build());
		qoa.setComparison(QoaComparison.MINIMUM);
		List<String> rpQoaList2 = qoaMappingService.determineRequestQoasWithDefault(Collections.emptyList(), qoaConfig);
		assertThat(rpQoaList2, is(List.of(RP_QOA_10)));

		qoa.getClasses().add(AcClass.builder().contextClass(RP_QOA_20).order(20).build());
		qoa.setComparison(QoaComparison.MAXIMUM);
		List<String> rpQoaList3 = qoaMappingService.determineRequestQoasWithDefault(Collections.emptyList(), qoaConfig);
		assertThat(rpQoaList3, is(List.of(RP_QOA_20)));

		List<String> stateQoaList = qoaMappingService.determineRequestQoasWithDefault(List.of("stateQoa"), qoaConfig);
		assertThat(stateQoaList, is(List.of("stateQoa")));
	}

	@Test
	void mapRequestQoasToOutboundTest() {
		var inboundClasses = List.of(RP_QOA_10, RP_QOA_20);
		var rpQoa = Qoa.builder().build();
		var rpQoaConfig = new QoaConfig(rpQoa, RP_ID);
		var comparison = QoaComparison.EXACT;

		var cpQoa = Qoa.builder()
					   .mapOutbound(true)
					   .singleQoaResponse(true) // ignored
					   .classes(List.of(AcClass.builder().contextClass(CP_QOA_10).order(10).build()))
					   .build();
		var cpQoaConfig = new QoaConfig(cpQoa, CP_ID);

		// no inbound classes
		assertThat(qoaMappingService.mapRequestQoasToOutbound(
						null, Collections.emptyList(), rpQoaConfig, cpQoaConfig),
				is(new QoaSpec(QoaComparison.EXACT, Collections.emptyList())));

		// no valid inbound mapping
		assertThat(qoaMappingService.mapRequestQoasToOutbound(
						null, inboundClasses, new QoaConfig(null, RP_ID), cpQoaConfig),
				is(new QoaSpec(QoaComparison.EXACT, inboundClasses)));
		assertThat(qoaMappingService.mapRequestQoasToOutbound(
						comparison, inboundClasses, rpQoaConfig, cpQoaConfig),
				is(new QoaSpec(comparison, inboundClasses)));

		// mapping one CP qoa, other unmapped
		rpQoa.setClasses(List.of(
				AcClass.builder().contextClass(RP_QOA_10).order(10).build(),
				AcClass.builder().contextClass(RP_QOA_20).order(20).build()));
		var qoaMap = givenGlobalQoa();
		when(trustBrokerProperties.getQoa()).thenReturn(qoaMap);
		assertThat(qoaMappingService.mapRequestQoasToOutbound(
						comparison, inboundClasses, rpQoaConfig, cpQoaConfig),
				is(new QoaSpec(comparison, List.of(CP_QOA_10, RP_QOA_20))));

		// requested minimum mapping
		assertThat(qoaMappingService.mapRequestQoasToOutbound(
						QoaComparison.MINIMUM, inboundClasses, rpQoaConfig, cpQoaConfig),
				is(new QoaSpec(QoaComparison.MINIMUM, List.of(CP_QOA_10))));

		// no inbound classes, fallback to defaults from RP
		assertThat(qoaMappingService.mapRequestQoasToOutbound(
						null, Collections.emptyList(), rpQoaConfig, cpQoaConfig),
				is(new QoaSpec(comparison, List.of(CP_QOA_10, RP_QOA_20))));

		// mapping from config wins - unmapped RP Qoa wins
		cpQoa.setComparison(QoaComparison.MAXIMUM);
		assertThat(qoaMappingService.mapRequestQoasToOutbound(
						QoaComparison.MINIMUM, inboundClasses, rpQoaConfig, cpQoaConfig),
				is(new QoaSpec(QoaComparison.MAXIMUM, List.of(RP_QOA_20))));
	}

	@Test
	void mapResponseQoasToOutboundTest() {
		var inboundClasses = List.of(CP_QOA_10, CP_QOA_20);
		var cpQoa = Qoa.builder()
					   .classes(
							   List.of(
									   AcClass.builder().contextClass(CP_QOA_10).order(10).build(),
									   AcClass.builder().contextClass(CP_QOA_20).order(20).build()
							   )
					   )
					   .build();
		var cpQoaConfig = new QoaConfig(cpQoa, CP_ID);
		var rpQoa = Qoa.builder()
					   .classes(
							   List.of(
									   AcClass.builder().contextClass(RP_QOA_10).order(10).build(),
									   AcClass.builder().contextClass(RP_QOA_20).order(20).build()
							   )
					   )
					   .build();
		var rpQoaConfig = new QoaConfig(rpQoa, RP_ID);

		// no mapping with empty RP Qoa
		assertThat(qoaMappingService.mapResponseQoasToOutbound(
						inboundClasses, cpQoaConfig, null, List.of(RP_QOA_20), new QoaConfig(null, RP_ID)),
				is(List.of(CP_QOA_10, CP_QOA_20)));

		// RP required max picks min from CP (ignoring RP list)
		assertThat(qoaMappingService.mapResponseQoasToOutbound(
						inboundClasses, cpQoaConfig, QoaComparison.MAXIMUM, List.of(RP_QOA_20), rpQoaConfig),
				is(List.of(RP_QOA_10)));

		// RP required min/better pick max from CP (ignoring RP list)
		assertThat(qoaMappingService.mapResponseQoasToOutbound(
						inboundClasses, cpQoaConfig, QoaComparison.MINIMUM, List.of(RP_QOA_10), rpQoaConfig),
				is(List.of(RP_QOA_20)));
		assertThat(qoaMappingService.mapResponseQoasToOutbound(
						inboundClasses, cpQoaConfig, QoaComparison.BETTER, List.of(RP_QOA_10), rpQoaConfig),
				is(List.of(RP_QOA_20)));

		// RP exact with default singleQoaResponse picks max from CP matching RP list
		assertThat(qoaMappingService.mapResponseQoasToOutbound(
						inboundClasses, cpQoaConfig, QoaComparison.EXACT, List.of(RP_QOA_10, RP_QOA_20), rpQoaConfig),
				is(List.of(RP_QOA_20)));
		assertThat(qoaMappingService.mapResponseQoasToOutbound(
						inboundClasses, cpQoaConfig, QoaComparison.EXACT, List.of(RP_QOA_10, "other"), rpQoaConfig),
				is(List.of(RP_QOA_10)));
		// list ignored if nothing matches
		assertThat(qoaMappingService.mapResponseQoasToOutbound(
						inboundClasses, cpQoaConfig, QoaComparison.EXACT, List.of("any", "other"), rpQoaConfig),
				is(List.of(RP_QOA_20)));
		assertThat(qoaMappingService.mapResponseQoasToOutbound(
						inboundClasses, cpQoaConfig, QoaComparison.EXACT, Collections.emptyList(), rpQoaConfig),
				is(List.of(RP_QOA_20)));

		// RP exact without singleQoaResponse maps all (ignoring RP list)
		rpQoaConfig.config().setSingleQoaResponse(false);
		assertThat(qoaMappingService.mapResponseQoasToOutbound(
						inboundClasses, cpQoaConfig, QoaComparison.EXACT, Collections.emptyList(), rpQoaConfig),
				is(List.of(RP_QOA_10, RP_QOA_20)));
		assertThat(qoaMappingService.mapResponseQoasToOutbound(
						inboundClasses, cpQoaConfig, QoaComparison.EXACT, List.of("any", RP_QOA_10), rpQoaConfig),
				is(List.of(RP_QOA_10, RP_QOA_20)));

	}

	@ParameterizedTest
	@MethodSource
	void determineComparisonTypeWithDefaultTest(QoaComparison comparison, Qoa qoa, QoaComparison expected) {
		assertThat(QoaMappingService.determineComparisonTypeWithDefault(comparison, qoa), is(expected));
	}

	static Object[][] determineComparisonTypeWithDefaultTest() {
		return new Object[][]{
				// default:
				{ null, null, QoaComparison.EXACT },
				// one source:
				{ QoaComparison.BETTER, Qoa.builder().build(), QoaComparison.BETTER },
				{ null, Qoa.builder().comparison(QoaComparison.MINIMUM).build(), QoaComparison.MINIMUM },
				// two sources, config wins:
				{ QoaComparison.BETTER, Qoa.builder().comparison(QoaComparison.MAXIMUM).build(), QoaComparison.MAXIMUM },
		};
	}

	@ParameterizedTest
	@MethodSource
	void canCpFulfillRequestQoasTest(QoaComparison comparison, List<String> requestedContextClasses,
									 Qoa rpQoa, Qoa cpQoa, boolean expected) {
		mockGlobalQoaMap();
		assertThat(qoaMappingService.canCpFulfillRequestQoas(comparison, requestedContextClasses,
						new QoaConfig(rpQoa, RP_ID), new QoaConfig(cpQoa, CP_ID)),
				is(expected));
	}

	static Object[][] canCpFulfillRequestQoasTest() {
		var defaultQoaEnforced = givenQoaConfig(true);
		var defaultQoaNotEnforced = givenQoaConfig(false);
		var acClassesMax50 = List.of(AcClass.builder()
											.order(59)
											.contextClass(SamlContextClass.SOFTWARE_PKI)
											.build());
		var cpQoaMax50NotEnforced = Qoa.builder()
									   .classes(acClassesMax50)
									   .build();
		return new Object[][]{
				// missing values
				{QoaComparison.EXACT, List.of(SamlContextClass.KERBEROS), null, null, true}, // no CP config
				{QoaComparison.EXACT, List.of(SamlContextClass.KERBEROS), defaultQoaEnforced, null, true}, // no CP config
				{QoaComparison.EXACT, List.of(SamlContextClass.KERBEROS), null, defaultQoaEnforced, false}, // CP config blocks
				{QoaComparison.EXACT, List.of(SamlContextClass.MOBILE_ONE_FACTOR_UNREGISTERED), null, defaultQoaEnforced, true},
				{QoaComparison.EXACT, List.of(SamlContextClass.KERBEROS), defaultQoaEnforced,
						Qoa.builder().enforce(true).build(), true}, // CP config has no context classes
				{null, null, defaultQoaEnforced, defaultQoaEnforced, true},
				{null, null, null, defaultQoaEnforced, true}, // no context classes requested
				// enforced, EXACT, matching
				{null, List.of(SamlContextClass.MOBILE_ONE_FACTOR_UNREGISTERED, SamlContextClass.PASSWORD_PROTECTED_TRANSPORT),
						defaultQoaEnforced, defaultQoaEnforced, true
				},
				{null, List.of(SamlContextClass.SOFTWARE_TIME_SYNC_TOKEN, SamlContextClass.SOFTWARE_PKI),
						defaultQoaEnforced, defaultQoaEnforced, true
				},
				// enforced, EXACT, missing
				{null, List.of(SamlContextClass.MOBILE_ONE_FACTOR_UNREGISTERED, SamlContextClass.PASSWORD_PROTECTED_TRANSPORT),
						defaultQoaEnforced, cpQoaMax50NotEnforced, false
				},
				{null, List.of(SamlContextClass.PASSWORD_PROTECTED_TRANSPORT, SamlContextClass.SOFTWARE_TIME_SYNC_TOKEN,
						SamlContextClass.KERBEROS),
						defaultQoaEnforced, defaultQoaEnforced, false
				},
				{null, List.of(SamlContextClass.PASSWORD_PROTECTED_TRANSPORT, SamlContextClass.SOFTWARE_TIME_SYNC_TOKEN,
						SamlContextClass.KERBEROS),
						defaultQoaNotEnforced, defaultQoaEnforced, false
				},
				// enforced, MINIMUM, within max cpQoa
				{QoaComparison.MINIMUM, List.of(SamlContextClass.MOBILE_ONE_FACTOR_UNREGISTERED,
						SamlContextClass.PASSWORD_PROTECTED_TRANSPORT),
						defaultQoaEnforced, defaultQoaEnforced, true
				},
				{QoaComparison.MINIMUM, List.of(SamlContextClass.MOBILE_ONE_FACTOR_UNREGISTERED, SamlContextClass.SOFTWARE_TIME_SYNC_TOKEN),
						defaultQoaEnforced, defaultQoaEnforced, true
				},
				{QoaComparison.MINIMUM, List.of(SamlContextClass.SOFTWARE_PKI),
						defaultQoaEnforced, defaultQoaEnforced, true
				},
				{QoaComparison.MINIMUM, List.of(SamlContextClass.SOFTWARE_PKI),
						defaultQoaEnforced, cpQoaMax50NotEnforced, true
				},
				// enforced, MINIMUM, above max cpQoa
				{QoaComparison.MINIMUM, List.of(DEFAULT_QOA_70),
						defaultQoaEnforced, cpQoaMax50NotEnforced, false
				},
				// not enforced, MINIMUM, above max cpQoa
				{QoaComparison.MINIMUM, List.of(DEFAULT_QOA_70),
						defaultQoaNotEnforced, cpQoaMax50NotEnforced, true
				},
		};
	}

	@ParameterizedTest
	@MethodSource
	void getReplacementAccClassesTest(Qoa qoa, int classCount) {
		var result = QoaMappingUtil.getReplacementAcClasses(qoa);
		assertTrue(result.isPresent());
		assertEquals(classCount, result.get().size());
	}

	static Object[][] getReplacementAccClassesTest() {
		var classesWithReplaceTrue = givenRpAcClasses();
		var classesWithReplaceFalse = new ArrayList<AcClass>();
		givenRpAcClasses().forEach(acClass -> {
					acClass.setReplaceInbound(Boolean.FALSE);
					classesWithReplaceFalse.add(acClass);
				}
		);
		var classes = givenRpAcClasses();
		classes.get(0).setReplaceInbound(Boolean.FALSE);
		return new Object[][]{
				{Qoa.builder().classes(classesWithReplaceTrue).build(), 3},
				{Qoa.builder().classes(classesWithReplaceFalse).build(), 0},
				{Qoa.builder().classes(classes).build(), 2}
		};
	}

	@Test
	void getQoaConfigurationTest() {
		var qoaRp = "urn:test:MOCKRP-QOA";
		var oidcClient = OidcClient.builder()
								   .id("client1")
								   .clientSecret("secret1")
								   .build();
		when(relyingPartiesMapping.getOidcClientConfigById(any(), any())).thenReturn(Optional.of(oidcClient));
		var stateData = StateData.builder().id("any").oidcClientId(qoaRp).build();
		var qoa = Qoa.builder().build();
		var relyingParty = givenRelyingParty(qoa);

		assertEquals(qoa, qoaMappingService.getQoaConfiguration(stateData, relyingParty).config());
	}

	private static RelyingParty givenRelyingParty(Qoa qoa) {
		return RelyingParty.builder()
						   .id("RELYING_PARTY_ID")
						   .qoa(qoa)
						   .build();
	}

	private static Qoa givenQoaConfig(Boolean enforce) {
		return Qoa.builder()
				  .classes(givenRpAcClasses())
				  .enforce(enforce)
				  .build();
	}

	private static List<AcClass> givenRpAcClasses() {
		List<AcClass> acClasses = new ArrayList<>();
		acClasses.add(AcClass.builder()
							 .order(70)
							 .contextClass("ANY70")
							 .build());
		acClasses.add(AcClass.builder()
							 .order(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getLevel())
							 .contextClass(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName())
							 .build());
		acClasses.add(AcClass.builder()
							 .order(SamlTestBase.Qoa.SOFTWARE_PKI.getLevel())
							 .contextClass(SamlTestBase.Qoa.SOFTWARE_PKI.getName())
							 .build());
		return acClasses;
	}

	private static QualityOfAuthenticationConfig givenGlobalQoa() {
		return QualityOfAuthenticationConfig.builder()
											.strongestPossible(SamlTestBase.Qoa.STRONGEST_POSSIBLE.getName())
											.build();
	}

	private void mockGlobalQoaMap() {
		var qoaMap = givenQoaGlobalMap();
		when(trustBrokerProperties.getQoaMap()).thenReturn(qoaMap);
	}

	private static Map<String, Integer> givenQoaGlobalMap() {
		Map<String, Integer> map = new HashMap<>();
		map.put(SamlContextClass.MOBILE_ONE_FACTOR_UNREGISTERED, 10);
		map.put(SamlContextClass.PASSWORD_PROTECTED_TRANSPORT, 20);
		map.put(SamlContextClass.SOFTWARE_TIME_SYNC_TOKEN, 30);
		map.put(SamlContextClass.KERBEROS, 40);
		map.put(SamlContextClass.SOFTWARE_PKI, 50);
		map.put(DEFAULT_QOA_70, 70);
		return map;
	}
}
