package org.springframework.boot.xss.defender.support;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import org.springframework.boot.xss.defender.XssDefender;
import org.springframework.boot.xss.defender.autoconfigure.XssDefenderConfiguration;
import org.springframework.util.StringUtils;

import java.io.IOException;

/**
 * This class is intended to process the XSS risk from JSON parameters.
 * With the help of {@link JsonDeserializer} from spring framework, we can
 * customize a json deserializer and determine how to deserialize a json string,
 * and add some secondary processing logic, so as to get rid of the potential XSS risk.
 *
 * @author codeboyzhou
 * @see XssDefender
 * @see XssDefenderConfiguration
 * @since 1.0.0
 */
public class StringXssJsonDeserializer extends JsonDeserializer<String> {

    /**
     * Whether the XSS defender is enabled.
     */
    private final boolean isXssDefenderEnabled;

    /**
     * An instance of {@link XssDefender}
     */
    private final XssDefender xssDefender;

    public StringXssJsonDeserializer(boolean isXssDefenderEnabled, XssDefender xssDefender) {
        this.isXssDefenderEnabled = isXssDefenderEnabled;
        this.xssDefender = xssDefender;
    }

    @Override
    public String deserialize(JsonParser parser, DeserializationContext context) throws IOException {
        final String json = parser.getValueAsString();
        return isXssDefenderEnabled ? xssDefender.defend(json) : StringUtils.trimWhitespace(json);
    }

}
