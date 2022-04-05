package org.springframework.boot.xss.defender.interceptor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.xss.defender.annotation.XssDefenderIgnore;
import org.springframework.boot.xss.defender.autoconfigure.XssDefenderProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This interceptor implements {@link HandlerInterceptor}, it mainly depends on the spring framework
 * to intercept http web request {@link HttpServletRequest}, and then find or parse the annotation
 * {@link XssDefenderIgnore} in order to determine whether needs to enable the XSS strategy.
 *
 * @author codeboyzhou
 * @see XssDefenderIgnore
 * @since 1.0.0
 */
@Configuration
public class XssDefenderInterceptor implements HandlerInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(XssDefenderInterceptor.class);

    /**
     * A chunk of common log message, just write once.
     */
    private static final String COMMON_WARN_MESSAGE = "it might expose a risk to your http request, please make sure you really need to do this.";

    /**
     * A properties object for spring boot auto configuration.
     */
    private final XssDefenderProperties properties;

    public XssDefenderInterceptor(XssDefenderProperties properties) {
        if (logger.isInfoEnabled()) {
            logger.info("Registered interceptor: {}", XssDefenderInterceptor.class);
        }
        this.properties = properties;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        // The defender is disabled.
        if (!properties.isEnabled()) {
            if (logger.isWarnEnabled()) {
                logger.warn("You have disabled the XSS defender, " + COMMON_WARN_MESSAGE);
            }
            return true;
        }

        // Ignore if the request is not from a web controller.
        final boolean isControllerRequest = handler instanceof HandlerMethod;
        if (!isControllerRequest) {
            return true;
        }

        HandlerMethod handlerMethod = (HandlerMethod) handler;

        // Check the XssDefenderIgnore annotation for controller class.
        Class<?> controller = handlerMethod.getMethod().getDeclaringClass();
        if (controller.isAnnotationPresent(XssDefenderIgnore.class)) {
            properties.disable();
            if (logger.isWarnEnabled()) {
                logger.warn("You have ignored the XSS defender for the whole class '{}', " + COMMON_WARN_MESSAGE, controller.getName());
            }
            return true;
        }

        // Check the XssDefenderIgnore annotation for handler method.
        if (handlerMethod.hasMethodAnnotation(XssDefenderIgnore.class)) {
            properties.disable();
            if (logger.isWarnEnabled()) {
                logger.warn("You have ignored the XSS defender for the request mapping '{}', " + COMMON_WARN_MESSAGE, request.getRequestURI());
            }
            return true;
        }

        return true;
    }

}
