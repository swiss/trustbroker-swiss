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

package swiss.trustbroker.common.saml.dto;

import lombok.Builder;
import lombok.Data;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.signature.Signature;

@Data
@Builder
public class SignatureParameters {

	private Credential credential;

	private String signatureAlgorithm;

	private String canonicalizationAlgorithm;

	private String digestMethod;

	private String skinnyAssertionNamespaces;

	public static SignatureParametersBuilder builderOf(Signature signature) {
		if (signature == null) {
			return builder();
		}
		var digestMethod = signature.getContentReferences().stream()
				.filter(SAMLObjectContentReference.class::isInstance)
				.map(ref -> ((SAMLObjectContentReference) ref).getDigestAlgorithm())
				.findFirst().orElse(null);
		return builder()
				.credential(signature.getSigningCredential())
				.signatureAlgorithm(signature.getSignatureAlgorithm())
				.canonicalizationAlgorithm(signature.getCanonicalizationAlgorithm())
				.digestMethod(digestMethod);
	}
}
