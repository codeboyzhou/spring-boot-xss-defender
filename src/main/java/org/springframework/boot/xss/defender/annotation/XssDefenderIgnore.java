package org.springframework.boot.xss.defender.annotation;

import org.springframework.boot.xss.defender.interceptor.XssDefenderInterceptor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.lang.annotation.*;

/**
 * This annotation determines whether a controller annotated by {@link Controller}
 * or {@link RestController} needs to ignore the XSS defense strategy.
 * <p>
 * At the same time, it can also be used on the controller methods annotated by
 * {@link GetMapping}, {@link PostMapping}, {@link RequestMapping}, similarly.
 *
 * @author codeboyzhou
 * @see XssDefenderInterceptor
 * @since 1.0.0
 */
@Inherited
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface XssDefenderIgnore {
}
