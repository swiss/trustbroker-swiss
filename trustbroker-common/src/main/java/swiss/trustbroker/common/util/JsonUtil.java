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

package swiss.trustbroker.common.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.shaded.gson.JsonArray;
import com.nimbusds.jose.shaded.gson.JsonElement;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParseException;
import com.nimbusds.jose.shaded.gson.JsonParser;
import com.nimbusds.jose.shaded.gson.JsonPrimitive;
import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.common.exception.TechnicalException;

@Slf4j
public class JsonUtil {

	private JsonUtil() {
	}

	static Object convertJsonElement(JsonElement element) {
		if (element == null) {
			return null;
		}
		if (element instanceof JsonObject obj) {
			return convertJsonObject(obj);
		}
		if (element instanceof JsonArray arr) {
			return convertJsonArray(arr);
		}
		if (element instanceof JsonPrimitive prim) {
			return convertJsonPrimitive(prim);
		}
		return element.getAsString();
	}

	private static ArrayList<Object> convertJsonArray(JsonArray arr) {
		var array = new ArrayList<>();
		for (var elt : arr.asList()) {
			array.add(convertJsonElement(elt));
		}
		return array;
	}

	private static Object convertJsonPrimitive(JsonPrimitive prim) {
		if (prim.isString()) {
			return prim.getAsString();
		}
		if (prim.isNumber()) {
			return prim.getAsNumber();
		}
		if (prim.isBoolean()) {
			return prim.getAsBoolean();
		}
		return prim.getAsString();
	}

	private static Map<String, Object> convertJsonObject(JsonObject obj) {
		var object = new HashMap<String, Object>();
		for (var entry : obj.asMap().entrySet()) {
			object.put(entry.getKey(), convertJsonElement(entry.getValue()));
		}
		return object;
	}

	static JsonElement parseJsonToElement(String jsonData, boolean tryOnly) {
		try {
			return JsonParser.parseString(jsonData);
		}
		catch (JsonParseException e) {
			if (tryOnly) {
				log.debug("JSON parsing failed: {}", e.getMessage());
				return null;
			}
			throw new TechnicalException(String.format("Json parsing failed: %s", e.getMessage()), e);
		}
	}

	/**
	 * @param tryOnly if true returns null in case of errors
	 * @param jsonData JSON (may be null)
	 * @return Map of property -> value for JSON objects, List of values for JSON arrays, or String value of primitives
	 */
	public static Object parseJson(String jsonData, boolean tryOnly) {
		return convertJsonElement(parseJsonToElement(jsonData, tryOnly));
	}

	/**
	 * @param tryOnly if true returns null in case of errors
	 * @param jsonData JSON (may be null)
	 * @return Map of property -> value containing List of values for JSON arrays, or String value of primitives
	 */
	@SuppressWarnings("java:S1168")
	public static Map<String, Object> parseJsonObject(String jsonData, boolean tryOnly) {
		var element = parseJsonToElement(jsonData, tryOnly);
		if (element instanceof JsonObject obj) {
			return convertJsonObject(obj);
		}
		if (element == null) {
			return null;
		}
		if (tryOnly) {
			log.debug("Not a JsonObject: class={}", element.getClass());
			return null;
		}
		throw new TechnicalException(String.format("Not a JsonObject: class=%s", element.getClass()));
	}

	/**
	 * @param tryOnly if true returns null in case of errors
	 * @param jsonData JSON (may be null)
	 * @return List of values for JSON arrays, containing Map of property -> value, List, or String value of primitives
	 */
	@SuppressWarnings("java:S1168")
	public static List<Object> parseJsonArray(String jsonData, boolean tryOnly) {
		var element = parseJsonToElement(jsonData, tryOnly);
		if (element instanceof JsonArray arr) {
			return convertJsonArray(arr);
		}
		if (element == null) {
			return null;
		}
		if (tryOnly) {
			log.debug("Not a JsonArray: class={}", element.getClass());
			return null;
		}
		throw new TechnicalException(String.format("Not a JsonArray: class=%s", element.getClass()));
	}

	/**
	 * @param jsonMap returned by parseJsonObject
	 * @param attribute
	 * @param expectedClass
	 * @return attribute from map or null if not found or not of expectedClass
	 * @param <T>
	 */
	public static <T> T getField(Map<String, Object> jsonMap, String attribute, Class<T> expectedClass) {
		if (jsonMap == null) {
			return null;
		}
		var element = jsonMap.get(attribute);
		if (expectedClass.isInstance(element)) {
			return expectedClass.cast(element);
		}
		return null;
	}

}
