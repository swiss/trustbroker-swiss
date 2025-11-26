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

package swiss.trustbroker.homerealmdiscovery.util;

import java.io.File;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.SerializationUtils;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ClaimsProvider;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderDefinitions;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderSetup;
import swiss.trustbroker.federation.xmlconfig.CounterParty;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.RelyingPartySetup;
import swiss.trustbroker.federation.xmlconfig.SsoGroupSetup;

@SuppressWarnings("unchecked")
@Slf4j
public class ClaimsProviderUtil {

	private ClaimsProviderUtil() {
	}

	// handle all SetupCP*.xml files
	public static ClaimsProviderSetup loadClaimsProviderSetup(String mappingFile) {
		var start = System.currentTimeMillis(); // we read from PVC residing on a network appliance
		var mapping = new File(mappingFile);
		var allCps = XmlConfigUtil.loadConfigFromDirectory(mapping, ClaimsProviderSetup.class);
		var ret = new ClaimsProviderSetup();
		allCps.result().forEach(cps -> ret.getClaimsParties().addAll(cps.getClaimsParties()));
		ret.getClaimsParties().forEach(ClaimsProviderUtil::postInit);
		reportDuplicateCounterParties(ret.getClaimsParties());
		log.info("Loaded {}Count={} definitions from setupCpFileCount={} {} files (skipping invalidCount={}) in dtMs={}",
				ClaimsParty.class.getSimpleName(), ret.getClaimsParties().size(), allCps.result().size(),
				mapping.getName(), allCps.skipped().size(), System.currentTimeMillis() - start);
		// add dummy entries for skipped files for status API:
		for (var skipped : allCps.skipped().entrySet()) {
			addInvalidClaimsParty(ret, skipped.getKey(), skipped.getValue(), null);
		}
		return ret;
	}

	public static void addInvalidClaimsParty(ClaimsProviderSetup claimsProviderSetup, String id,
			Exception exception, String errorText) {
		var cp = ClaimsParty.builder().id(id).build();
		if (exception != null) {
			cp.invalidate(exception);
		}
		else {
			cp.invalidate(errorText);
		}
		claimsProviderSetup.getClaimsParties().add(cp);
	}

	private static void postInit(ClaimsParty claimsParty) {
		// transition of configs
	}

	// handle all SetupRP*.xml files
	public static RelyingPartySetup loadRelyingPartySetup(String mappingFile) {
		return loadRelyingPartySetup(new File(mappingFile));
	}

	public static RelyingPartySetup loadRelyingPartySetup(File mappingFile) {
		var start = System.currentTimeMillis(); // we read from PVC residing on a network appliance
		var allRps = XmlConfigUtil.loadConfigFromDirectory(mappingFile, RelyingPartySetup.class);
		var ret = new RelyingPartySetup();
		allRps.result().forEach(rps -> ret.getRelyingParties().addAll(rps.getRelyingParties()));
		var countWithoutAliases = ret.getRelyingParties().size();
		var rpIds = reportDuplicateCounterParties(ret.getRelyingParties());
		replicateRelyingPartiesByHrdAlias(ret.getRelyingParties(), rpIds); // register aliases
		var countWithAliases = ret.getRelyingParties().size();
		var oidcClientCount = new AtomicInteger();
		ret.getRelyingParties().forEach(rp -> oidcClientCount.addAndGet(rp.getOidcClients().size()));
		log.info("Loaded {}Count={} definitions from setupRpFileCount={} {} files "
						+"(adding relyingPartyAliasCount={} oidcClientCount={}  skipping invalidCount={}) in dtMs={}",
				RelyingParty.class.getSimpleName(), countWithoutAliases, allRps.result().size(),
				mappingFile.getName(), (countWithAliases - countWithoutAliases), oidcClientCount, allRps.skipped().size(),
				System.currentTimeMillis() - start);
		// add dummy entries for skipped files for status API:
		for (var skipped : allRps.skipped().entrySet()) {
			addInvalidRelyingParty(ret, skipped.getKey(), skipped.getValue(), null);
		}
		return ret;
	}

	public static void addInvalidRelyingParty(RelyingPartySetup claimsProviderSetup, String id,
			Exception exception, String errorText) {
		var rp = RelyingParty.builder().id(id).build();
		if (exception != null) {
			rp.invalidate(exception);
		}
		else {
			rp.invalidate(errorText);
		}
		claimsProviderSetup.getRelyingParties().add(rp);
	}

	private static Set<String> reportDuplicateCounterParties(List<? extends CounterParty> counterParties) {
		var idSet = new HashSet<String>();
		for (var counterParty : counterParties) {
			if (idSet.contains(counterParty.getId())) {
				log.error("Duplicate {} issuerId={}", counterParty.getShortType(), counterParty.getId());
			}
			idSet.add(counterParty.getId());
		}
		return idSet;
	}

	public static RelyingParty loadRelyingParty(String mappingFile) {
		var mapping = new File(mappingFile);
		return XmlConfigUtil.loadConfigFromFile(mapping, RelyingParty.class);
	}

	public static ClaimsProviderDefinitions loadClaimsProviderDefinitions(String mappingFile) {
		var start = System.currentTimeMillis(); // we read from PVC residing on a network appliance
		var mapping = new File(mappingFile);
		var ret = XmlConfigUtil.loadConfigFromFile(mapping, ClaimsProviderDefinitions.class);
		log.info("Loaded {}Count={} definitions from one {} file in dtMs={}",
				ClaimsProviderDefinitions.class.getSimpleName(), ret.getClaimsProviders().size(),
				mapping.getName(), System.currentTimeMillis() - start);
		return ret;
	}

	public static SsoGroupSetup loadSsoGroups(String ssoGroupsSetupFileName) {
		var ssoGroupsSetupFile = new File(ssoGroupsSetupFileName);
		if (!ssoGroupsSetupFile.exists()) {
			// we have too many setup files and SSOGroups are special, so get rid of the Setup prefix in a backward compat way
			ssoGroupsSetupFile = new File(ssoGroupsSetupFileName.replace("SetupSSOGroups", "SSOGroups"));
		}
		return XmlConfigUtil.loadConfigFromFile(ssoGroupsSetupFile, SsoGroupSetup.class);
	}

	// handle derived IDs, so we can merge RelyingParty X with X-...
	public static void replicateRelyingPartiesByHrdAlias(List<RelyingParty> relyingParties, Set<String> rpIds) {
		var aliasList = new ArrayList<RelyingParty>();
		relyingParties.forEach(relyingParty -> {
			log.debug("Adding primary rpIssuer={}", relyingParty.getId());
			var mappings = relyingParty.getClaimsProviderMappings();
			if (mappings != null) {
				var claimProviders = mappings.getClaimsProviderList();
				if (claimProviders != null) {
					claimProviders.forEach(claimProvider ->
						addAliasesForClaimsProvider(rpIds, aliasList, relyingParty, claimProvider)
					);
				}
			}
		});
		relyingParties.addAll(aliasList);
	}

	private static void addAliasesForClaimsProvider(Set<String> rpIds,
			ArrayList<RelyingParty> aliasList, RelyingParty relyingParty, ClaimsProvider claimProvider) {
		var alias = claimProvider.getRelyingPartyAlias();
		if (alias != null) {
			var rpAliasCopy = SerializationUtils.clone(relyingParty);
			rpAliasCopy.setUnaliasedId(rpAliasCopy.getId());
			rpAliasCopy.setId(alias);
			if (rpIds.contains(rpAliasCopy.getId())) {
				log.error("Adding duplicate alias={} for rpIssuer={} skipped."
								+ " HINT: Check SetupRP files for ambiguous 'id' and 'relyingPartyAlias' attributes.",
						alias, relyingParty.getId());
			}
			else {
				aliasList.add(rpAliasCopy);
				rpIds.add(alias);
				log.debug("Adding alias={} for rpIssuer={}", alias, relyingParty.getId());
			}
		}
	}

}
