// script derives an attribute from another one
package scripts

// query
LOG.info("ORIGIN attribute by name: {}", CPResponse.getAttribute("ORIGIN1"))
LOG.info("IDM user detail by short name: {}", CPResponse.getUserDetails("SHORT1"))
LOG.info("IDM user detail by long name: {}", CPResponse.getUserDetails("LONG1"))

// origin attributes
CPResponse.setAttribute("ORIGIN2", "ORIGINVALUE2")
CPResponse.setAttributes("ORIGIN3", List.of("ORIGINVALUE3"))
CPResponse.removeAttributes("ORIGIN1")

// user details
CPResponse.setUserDetail("SHORT2", "LONG2", "VALUE2")
CPResponse.setUserDetails("SHORT3", "LONG3", List.of("VALUE3"))
CPResponse.removeUserDetails("SHORT1")
