package org.springframework.boot.xss.defender.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.xss.defender.DefenseStrategy;

/**
 * A properties class for spring boot auto configuration. You can configure its fields
 * in the application.yml or application.properties, prefix is 'spring.xss-defender'.
 *
 * @author codeboyzhou
 * @see XssDefenderConfiguration
 * @since 1.0.0
 */
@ConfigurationProperties(prefix = XssDefenderProperties.PREFIX)
public class XssDefenderProperties {

    /**
     * The configuration prefix for application.yml or application.properties, package-private.
     */
    static final String PREFIX = "spring.xss-defender";

    /**
     * Whether to enable XSS defender, default value is {@code true}.
     */
    private boolean enabled = true;

    /**
     * The XSS defense strategy, default value is {@code DefenseStrategy.TRIM}.
     *
     * @see DefenseStrategy
     */
    private DefenseStrategy strategy = DefenseStrategy.TRIM;

    /**
     * Whether continue to escape the input text after XSS safe trim, default value is {@code false}.
     * <p>
     * NOTICE: It won't be effective unless the value of {@link DefenseStrategy} is {@code TRIM}.
     */
    private boolean escapeAfterTrim = false;

    public boolean isEnabled() {
        return enabled;
    }

    public void disable() {
        this.enabled = false;
    }

    public DefenseStrategy getStrategy() {
        return strategy;
    }

    public boolean isEscapeAfterTrimEnabled() {
        return escapeAfterTrim;
    }

}
