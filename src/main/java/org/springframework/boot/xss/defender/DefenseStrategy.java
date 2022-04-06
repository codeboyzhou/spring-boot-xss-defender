package org.springframework.boot.xss.defender;

import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.springframework.boot.xss.defender.exception.UnsupportedXssDefenseStrategyException;
import org.springframework.web.util.HtmlUtils;

/**
 * The enums of XSS defense strategy
 *
 * @author codeboyzhou
 * @see XssDefender
 * @since 1.0.0
 */
public enum DefenseStrategy {
    /**
     * If this value is used, the {@link XssDefender} will trim all the risky XSS characters held by
     * input text when XSS risk detected, {@link Jsoup#clean(String, Safelist)} will finish it actually.
     */
    TRIM,

    /**
     * If this value is used, the {@link XssDefender} will escape all the risky XSS characters held by
     * input text when XSS risk detected, {@link HtmlUtils#htmlEscape(String, String)} will finish it actually.
     */
    ESCAPE,

    /**
     * If this value is used, the {@link XssDefender} will throw an runtime exception directly when XSS risk detected.
     *
     * @see UnsupportedXssDefenseStrategyException
     */
    THROW
}
