package org.springframework.boot.xss.defender;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import org.springframework.boot.xss.defender.autoconfigure.XssDefenderConfiguration;
import org.springframework.boot.xss.defender.autoconfigure.XssDefenderProperties;
import org.springframework.util.StringUtils;

import java.io.IOException;

/**
 * This class is intended to process the XSS risk from JSON parameters.
 * With the help of {@link JsonDeserializer} from spring framework, we can
 * customize how to deserialize a JSON string and add some secondary processing
 * logic, so as to get rid of the potential XSS risk.
 *
 * @author codeboyzhou
 * @see XssDefender
 * @see XssDefenderConfiguration
 * @since 1.0.0
 */
public class JsonXssDefender extends JsonDeserializer<String> implements XssDefender {

    /**
     * A properties object for spring boot auto configuration.
     */
    private final XssDefenderProperties properties;

    public JsonXssDefender(XssDefenderProperties properties) {
        this.properties = properties;
    }

    @Override
    public String deserialize(JsonParser parser, DeserializationContext context) throws IOException {
        final String json = parser.getValueAsString();
        return properties.isEnabled() ? defend(properties, json) : StringUtils.trimWhitespace(json);
    }

}
