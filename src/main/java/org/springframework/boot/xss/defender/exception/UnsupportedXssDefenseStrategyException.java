package org.springframework.boot.xss.defender.exception;

import org.springframework.boot.xss.defender.DefenseStrategy;

/**
 * This runtime exception will be thrown when an unsupported value of {@link DefenseStrategy} is configured.
 *
 * @author codeboyzhou
 * @see DefenseStrategy
 * @since 1.0.0
 */
public class UnsupportedXssDefenseStrategyException extends UnsupportedOperationException {

    public UnsupportedXssDefenseStrategyException(String message) {
        super(message);
    }

}
