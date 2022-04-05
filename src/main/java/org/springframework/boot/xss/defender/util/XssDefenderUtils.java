package org.springframework.boot.xss.defender.util;

import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.xss.defender.DefenseStrategy;
import org.springframework.boot.xss.defender.autoconfigure.XssDefenderProperties;
import org.springframework.boot.xss.defender.exception.UnsupportedXssDefenseStrategyException;
import org.springframework.boot.xss.defender.exception.XssRiskDetectedException;
import org.springframework.util.StringUtils;
import org.springframework.web.util.HtmlUtils;

import java.nio.charset.StandardCharsets;

/**
 * This class is mainly responsible for processing the actual input text,
 * implements different defense logic according to the different XSS defense strategy has been configured.
 *
 * @author codeboyzhou
 * @since 1.0.0
 */
public class XssDefenderUtils {

    private static final Logger logger = LoggerFactory.getLogger(XssDefenderUtils.class);

    /**
     * Process the actual input text
     *
     * @param properties The instance of {@link XssDefenderProperties}
     * @param text       The actual input text
     * @return The safe text without XSS risk
     */
    public static String defend(XssDefenderProperties properties, String text) {
        if (StringUtils.hasText(text)) {
            // Trim leading and trailing whitespace.
            text = StringUtils.trimWhitespace(text);

            DefenseStrategy defenseStrategy = properties.getStrategy();
            final boolean isEscapeAfterTrimEnabled = properties.isEscapeAfterTrimEnabled();

            if (defenseStrategy == DefenseStrategy.TRIM) {
                return trim(text, isEscapeAfterTrimEnabled);
            } else if (defenseStrategy == DefenseStrategy.ESCAPE) {
                return escape(text);
            } else if (defenseStrategy == DefenseStrategy.THROW) {
                throw new XssRiskDetectedException(text);
            } else {
                throw new UnsupportedXssDefenseStrategyException(defenseStrategy.name().toLowerCase());
            }
        }

        // Avoid NullPointerException
        return "";
    }

    /**
     * Trim all the XSS risky characters, and check if the escape-after-trim will be necessary.
     *
     * @param text                     The actual input text
     * @param isEscapeAfterTrimEnabled The escape-after-trim is enable or not
     * @return The safe text without XSS risk
     */
    private static String trim(String text, boolean isEscapeAfterTrimEnabled) {
        final String cleanedText = Jsoup.clean(text, Safelist.basic());
        if (logger.isDebugEnabled()) {
            logger.debug("Trim text for XSS defense, input: {}, output: {}", text, cleanedText);
        }

        if (isEscapeAfterTrimEnabled) {
            return escape(cleanedText);
        }

        return cleanedText;
    }

    /**
     * Escape all the XSS risky characters.
     *
     * @param text The actual input text
     * @return The safe text without XSS risk
     */
    private static String escape(String text) {
        return HtmlUtils.htmlEscape(text, StandardCharsets.UTF_8.name());
    }

}
