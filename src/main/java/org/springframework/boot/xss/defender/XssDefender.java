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
 * This class is mainly responsible for processing the actual input text.
 * Implements different defense logic according to the different XSS defense strategy.
 *
 * @author codeboyzhou
 * @since 1.0.0
 */
public class XssDefender {

    private static final Logger logger = LoggerFactory.getLogger(XssDefender.class);

    /**
     * Empty string constant.
     */
    public static final String EMPTY_STRING = "";

    /**
     * Escaped empty string constant, for printing more clear log information.
     */
    private static final String ESCAPED_EMPTY_STRING = "\"\"";

    /**
     * The XSS defense strategy.
     *
     * @see DefenseStrategy
     */
    private final String defenseStrategy;

    /**
     * Whether continue to escape the input text after XSS safe trim.
     *
     * @see XssDefenderProperties#isEscapeAfterTrimEnabled()
     */
    private final boolean needEscapeAfterTrim;

    public XssDefender(String defenseStrategy, boolean needEscapeAfterTrim) {
        this.defenseStrategy = defenseStrategy;
        this.needEscapeAfterTrim = needEscapeAfterTrim;
    }

    /**
     * Process the actual input text.
     *
     * @param text The actual input text
     * @return The safe text without XSS risk
     */
    public String defend(String text) {
        return StringUtils.hasText(text) ? this.doDefend(text) : EMPTY_STRING;
    }

    /**
     * A helper method of {@link #defend(String)}
     */
    private String doDefend(String text) {
        // Trim leading and trailing whitespace.
        text = StringUtils.trimWhitespace(text);

        if (DefenseStrategy.isTrim(defenseStrategy)) {
            return this.trim(text);
        } else if (DefenseStrategy.isEscape(defenseStrategy)) {
            return this.escape(text);
        } else if (DefenseStrategy.isThrow(defenseStrategy)) {
            this.checkAndThrow(text);
        } else {
            throw new UnsupportedXssDefenseStrategyException(defenseStrategy);
        }

        return text;
    }

    /**
     * Trim all the XSS risky characters, and check if the escape-after-trim option is set {@code true}.
     *
     * @param text The actual input text
     * @return The safe text without XSS risk
     */
    private String trim(String text) {
        String safeText = Jsoup.clean(text, Safelist.basic());
        if (needEscapeAfterTrim) {
            safeText = HtmlUtils.htmlEscape(safeText, StandardCharsets.UTF_8.name());
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Trim text to prevent XSS risk, escape-after-trim option: {}, input: {}, output: {}",
                    needEscapeAfterTrim, text, safeText.isEmpty() ? ESCAPED_EMPTY_STRING : safeText);
        }

        if (safeText.length() != text.length() && logger.isWarnEnabled()) {
            logger.warn("XSS risk detected in the input parameter: {}, escape-after-trim option: {}, cleaned text: {}",
                    text, needEscapeAfterTrim, safeText.isEmpty() ? ESCAPED_EMPTY_STRING : safeText);
        }

        return safeText;
    }

    /**
     * Escape all the XSS risky characters.
     *
     * @param text The actual input text
     * @return The safe text without XSS risk
     */
    private String escape(String text) {
        final String safeText = HtmlUtils.htmlEscape(text, StandardCharsets.UTF_8.name());
        if (logger.isWarnEnabled()) {
            logger.warn("XSS risk detected in the input parameter: {}, escaped text: {}", text, safeText);
        }
        return safeText;
    }

    /**
     * Check if the input text is xss-safe, an exception will be thrown if the answer is false.
     *
     * @param text The actual input text
     */
    private void checkAndThrow(String text) {
        final boolean isValidText = Jsoup.isValid(text, Safelist.basic());

        if (isValidText && logger.isDebugEnabled()) {
            logger.debug("Checking XSS risk, the input text is safe: {}", text);
        }

        if (!isValidText) {
            throw new XssRiskDetectedException(text);
        }
    }

}
