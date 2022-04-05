package org.springframework.boot.xss.defender.exception;

import org.springframework.boot.xss.defender.DefenseStrategy;

/**
 * This runtime exception will be thrown when the value of {@link DefenseStrategy} is configured as {@code THROW}.
 * Your main application can try-catch this exception and do something, for example, return message to front.
 *
 * @author codeboyzhou
 * @see DefenseStrategy
 * @since 1.0.0
 */
public class XssRiskDetectedException extends IllegalArgumentException {

    public XssRiskDetectedException(String message) {
        super(message);
    }

}
