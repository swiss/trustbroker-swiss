// testing OIDC claims processing

package scripts

if (CPResponse.rpContext?.get("Referer")?.startsWith("https://identity")) {
	LOG.info("OIDC claim transformation from: {}", CPResponse)

	// IDP input
	CPResponse.attributes.forEach({ key, value -> key.setNamespaceUri(key.getNamespaceUri()?.replaceAll(".*/", "")) })

	// IDM output
	CPResponse.userDetails.forEach({ key, value -> key.setNamespaceUri(key.getNamespaceUri().replaceAll(".*/", "")) })

	// computed
	CPResponse.properties.forEach({ key, value -> key.setNamespaceUri(key.getNamespaceUri().replaceAll(".*/", "")) })

	LOG.info("OIDC claim transformation to: {}", CPResponse)
}
