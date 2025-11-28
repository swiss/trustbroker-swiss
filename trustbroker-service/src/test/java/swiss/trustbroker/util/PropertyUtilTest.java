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

package swiss.trustbroker.util;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.federation.xmlconfig.SecurityPolicies;

class PropertyUtilTest {

	private static class TestDto {

		private String rwString;

		private Boolean roBoolean;

		private int rwInt;

		private Double rwDouble;

		private Integer rwInteger;

		public String getRwString() {
			return rwString;
		}

		public void setRwString(String rwString) {
			this.rwString = rwString;
		}

		public Boolean getRoBoolean() {
			return roBoolean;
		}

		public int getRwInt() {
			return rwInt;
		}

		public void setRwInt(int rwInt) {
			this.rwInt = rwInt;
		}

		public Double getRwDouble() {
			return rwDouble;
		}

		public void setRwDouble(Double rwDouble) {
			this.rwDouble = rwDouble;
		}

		public Integer getRwInteger() {
			return rwInteger;
		}

		public void setRwInteger(Integer rwInteger) {
			this.rwInteger = rwInteger;
		}

	}

	@Test
	void copyAttributeIfMissingNullObjects() {
		assertThat(PropertyUtil.copyAttributeIfMissing(null, null, null, null), is(true));
		assertThat(PropertyUtil.copyAttributeIfMissing(null, null, new TestDto(), null), is(true));
		assertThat(PropertyUtil.copyAttributeIfMissing(null, null, null, new TestDto()), is(true));
	}

	@Test
	void copyAttributeIfMissingNullBase() {
		var expected = "expected";
		var base = new TestDto();
		var target = new TestDto();
		target.setRwString(expected);
		assertThat(PropertyUtil.copyAttributeIfMissing(TestDto::setRwString, TestDto::getRwString, target, base), is(true));
		// no changes
		assertThat(target.getRwString(), is(expected));
		assertThat(base.getRwString(), is(nullValue()));
	}

	@Test
	void copyAttributeIfMissingNullTarget() {
		var expected = "expected";
		var base = new TestDto();
		base.setRwString(expected);
		var target = new TestDto();
		assertThat(PropertyUtil.copyAttributeIfMissing(TestDto::setRwString, TestDto::getRwString, target, base), is(true));
		// value copied
		assertThat(target.getRwString(), is(expected));
		// no change in base
		assertThat(base.getRwString(), is(expected));
	}

	@Test
	void copyAttributeIfMissingNeedsMerge() {
		var baseValue = "base";
		var override = "override";
		var base = new TestDto();
		base.setRwString(baseValue);
		var target = new TestDto();
		target.setRwString(override);
		assertThat(PropertyUtil.copyAttributeIfMissing(TestDto::setRwString, TestDto::getRwString, target, base), is(false));
		// no changes
		assertThat(target.getRwString(), is(override));
		assertThat(base.getRwString(), is(baseValue));
	}

	@Test
	void copyAttributeIfBlankTargetBlank() {
		var baseValue = "base";
		var base = new TestDto();
		base.setRwString(baseValue);
		var target = new TestDto();
		target.setRwString("");
		assertThat(PropertyUtil.copyAttributeIfBlank(TestDto::setRwString, TestDto::getRwString, target, base), is(true));
		// no changes
		assertThat(target.getRwString(), is(baseValue));
		assertThat(base.getRwString(), is(baseValue));
	}

	@Test
	void copyAttributeIfRequiredTargetInvalid() {
		var baseValue = "basetoolong";
		var override = "overridetoolong";
		var base = new TestDto();
		base.setRwString(baseValue);
		var target = new TestDto();
		target.setRwString(override);
		assertThat(PropertyUtil.copyAttributeIfRequired(TestDto::setRwString, TestDto::getRwString, target, base,
				PropertyUtilTest::checkLength), is(true));
		// no changes
		assertThat(target.getRwString(), is(override));
		assertThat(base.getRwString(), is(baseValue));
	}

	@Test
	void copyAttributeIfRequiredBothInvalid() {
		var baseValue = "base";
		var base = new TestDto();
		base.setRwString(baseValue);
		var target = new TestDto();
		target.setRwString("toolongvalue");
		assertThat(PropertyUtil.copyAttributeIfRequired(TestDto::setRwString, TestDto::getRwString, target, base,
				PropertyUtilTest::checkLength), is(true));
		// no changes
		assertThat(target.getRwString(), is(baseValue));
		assertThat(base.getRwString(), is(baseValue));
	}

	public static boolean checkLength(String value) {
		return value != null && value.length() > 5;
	}

	@Test
	void copyMissingAttributes() {
		var baseStr = "baseStr";
		var baseInt = 1;
		var baseBoolean = Boolean.FALSE;
		var baseDouble = 2.0;
		var base = new TestDto();
		base.setRwString(baseStr);
		base.setRwInt(baseInt);
		base.roBoolean = baseBoolean;
		base.setRwDouble(baseDouble);
		var target = new TestDto();
		var overrideDouble = 3.0;
		var overrideInteger = 6;
		target.setRwDouble(overrideDouble);
		target.setRwInteger(overrideInteger);
		PropertyUtil.copyMissingAttributes(target, base);
		// value copied
		assertThat(target.getRwString(), is(baseStr)); // null in target
		assertThat(target.getRwInt(), is(0)); // primitives are never copied as they are never null
		// value not copied
		assertThat(target.getRoBoolean(), is(nullValue())); // no setter
		assertThat(target.getRwDouble(), is(overrideDouble)); // set in both
		assertThat(target.getRwInteger(), is(overrideInteger)); // null in base
		// no change in base
		assertThat(base.getRwString(), is(baseStr));
		assertThat(base.getRwInt(), is(baseInt));
		assertThat(base.getRoBoolean(), is(baseBoolean));
		assertThat(base.getRwDouble(), is(baseDouble));
		assertThat(base.getRwInteger(), is(nullValue()));
	}

	@Test
	void copyMissingAttributesSameOrNull() {
		var base = new TestDto();
		var baseStr = "baseStr";
		base.setRwString(baseStr);

		assertDoesNotThrow(() -> PropertyUtil.copyMissingAttributes(null, base));
		assertDoesNotThrow(() -> PropertyUtil.copyMissingAttributes(base, null));
		assertDoesNotThrow(() -> PropertyUtil.copyMissingAttributes(base, base));
		assertDoesNotThrow(() -> PropertyUtil.copyAttributeIfMissing(TestDto::setRwString, TestDto::getRwString, null, base));
		assertDoesNotThrow(() -> PropertyUtil.copyAttributeIfMissing(TestDto::setRwString, TestDto::getRwString, base, null));
		assertDoesNotThrow(() -> PropertyUtil.copyAttributeIfMissing(TestDto::setRwString, TestDto::getRwString, base, base));

		assertThat(base.getRwString(), is(baseStr));
	}

	@Test
	void copyMissingAttributesFiltered() {
		var baseStr = "baseStr";
		var baseDouble = 2.0;
		var base = new TestDto();
		base.setRwString(baseStr);
		base.setRwDouble(baseDouble);
		var target = new TestDto();
		PropertyUtil.copyMissingAttributes(Set.of("rwString"), target, base);
		// value copied
		assertThat(target.getRwString(), is(baseStr)); // null in target
		// value not copied
		assertThat(target.getRwDouble(), is(nullValue())); // set in both, but not in list
		assertThat(target.getRoBoolean(), is(nullValue())); // no setter
		assertThat(target.getRwInt(), is(0)); // primitive
		assertThat(target.getRwInteger(), is(nullValue())); // null in both
		// no change in base
		assertThat(base.getRwString(), is(baseStr));
		assertThat(base.getRwDouble(), is(baseDouble));
		assertThat(base.getRwInt(), is(0));
		assertThat(base.getRoBoolean(), is(nullValue()));
		assertThat(base.getRwInteger(), is(nullValue()));
	}

	@ParameterizedTest
	@CsvSource(value = { "undefined", "roBoolean" })
	void copyMissingAttributesUnmatched(String property) {
		var base = new TestDto();
		var target = new TestDto();
		var properties = Set.of(property);
		assertThrows(TechnicalException.class, () -> PropertyUtil.copyMissingAttributes(properties, target, base));
	}

	@Test
	void copyMissingAttributesMatched() {
		var base = new TestDto();
		var target = new TestDto();
		var properties = Set.of("rwString", "rwInt", "rwDouble", "rwInteger");
		assertDoesNotThrow(() -> PropertyUtil.copyMissingAttributes(properties, target, base));
	}

	@Test
	void mergeSecurityPolicies() {
		var base = SecurityPolicies.builder()
				.notOnOrAfterSeconds(3600)
				.requireSignedAuthnRequest(true)
				.build();

		var rp1 = SecurityPolicies.builder()
				.notOnOrAfterSeconds(28800)
				.requireSignedAuthnRequest(false)
				.requireSignedLogoutRequest(false)
				.build();
		PropertyUtil.copyMissingAttributes(rp1, base);
		assertThat(rp1.getNotOnOrAfterSeconds(), equalTo(28800));
		assertThat(rp1.getRequireSignedAuthnRequest(), equalTo(false));
		assertThat(rp1.getRequireSignedLogoutRequest(), equalTo(false));
		assertThat(rp1.getSsoMinQoaLevel(), is(nullValue()));
	}


	@ParameterizedTest
	@CsvSource(value = {
			"null,null,null",
			"null,true,true",
			"true,false,true"
	}, nullValues = "null")
	void evaluateSecurityPolicy(Boolean input, Boolean defaultValue, Boolean expected) {
		var securityPolicies = new SecurityPolicies();
		securityPolicies.setDelegateOrigin(input);
		var result = PropertyUtil.evaluatePropery(securityPolicies, SecurityPolicies::getDelegateOrigin,
				() -> defaultValue);
		assertThat(result, is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,null",
			"null,1,1",
			"0,2,2",
			"-1,4,4",
			"3,5,3",
			"3,null,3"
	}, nullValues = "null")
	void evaluateSecurityPolicy(Integer input, Integer defaultValue, Integer expected) {
		var securityPolicies = new SecurityPolicies();
		securityPolicies.setAudienceNotOnOrAfterSeconds(input);
		var result = PropertyUtil.evaluatePositiveNumberProperty(securityPolicies,
				SecurityPolicies::getAudienceNotOnOrAfterSeconds,
				() -> defaultValue);
		assertThat(result, is(expected));
	}


}
