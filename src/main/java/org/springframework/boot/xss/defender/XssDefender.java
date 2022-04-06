package org.springframework.boot.xss.defender;

import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
public interface XssDefender {

    Logger logger = LoggerFactory.getLogger(XssDefender.class);

    /**
     * Empty string constant.
     */
    String EMPTY_STRING = "";

    /**
     * Process the actual input text.
     *
     * @param properties The instance of {@link XssDefenderProperties}
     * @param text       The actual input text
     * @return The safe text without XSS risk
     */
    default String defend(XssDefenderProperties properties, String text) {
        if (StringUtils.hasText(text)) {
            // Trim leading and trailing whitespace.
            text = StringUtils.trimWhitespace(text);

            DefenseStrategy defenseStrategy = properties.getStrategy();
            final boolean isEscapeAfterTrimEnabled = properties.isEscapeAfterTrimEnabled();

            if (defenseStrategy == DefenseStrategy.TRIM) {
                return this.trim(text, isEscapeAfterTrimEnabled);
            } else if (defenseStrategy == DefenseStrategy.ESCAPE) {
                return this.escape(text);
            } else if (defenseStrategy == DefenseStrategy.THROW) {
                throw new XssRiskDetectedException(text);
            } else {
                throw new UnsupportedXssDefenseStrategyException(defenseStrategy.name().toLowerCase());
            }
        }

        // Annoying NPE
        return EMPTY_STRING;
    }

    /**
     * Trim all the XSS risky characters, and check if the escape-after-trim will be necessary.
     *
     * @param text                     The actual input text
     * @param isEscapeAfterTrimEnabled The escape-after-trim is enable or not
     * @return The safe text without XSS risk
     */
    default String trim(String text, boolean isEscapeAfterTrimEnabled) {
        final String cleanedText = Jsoup.clean(text, Safelist.basic());

        if (logger.isDebugEnabled()) {
            logger.debug("Trim text to prevent XSS risk, input: {}, output (maybe is empty): {}", text, cleanedText);
        }

        if (cleanedText.length() != text.length() && logger.isWarnEnabled()) {
            logger.warn("XSS risk detected in the input parameter: {}, cleaned text (maybe empty) is: {}", text, cleanedText);
        }

        return isEscapeAfterTrimEnabled ? this.escape(cleanedText) : cleanedText;
    }

    /**
     * Escape all the XSS risky characters.
     *
     * @param text The actual input text
     * @return The safe text without XSS risk
     */
    default String escape(String text) {
        return HtmlUtils.htmlEscape(text, StandardCharsets.UTF_8.name());
    }

}
