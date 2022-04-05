package org.springframework.boot.xss.defender.autoconfigure;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.xss.defender.FormXssDefender;
import org.springframework.boot.xss.defender.interceptor.XssDefenderInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Add some auto configurations, for example, interceptors, and some essential java beans.
 *
 * @author codeboyzhou
 * @see XssDefenderProperties
 * @see XssDefenderInterceptor
 * @see FormXssDefender
 * @since 1.0.0
 */
@EnableConfigurationProperties(XssDefenderProperties.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = XssDefenderProperties.PREFIX, name = "enabled", havingValue = "true", matchIfMissing = true)
public class XssDefenderConfiguration implements WebMvcConfigurer {

    /**
     * A properties object for spring boot auto configuration.
     */
    private XssDefenderProperties properties;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new XssDefenderInterceptor(properties)).order(Ordered.LOWEST_PRECEDENCE);
    }

    @Bean
    public FormXssDefender formXssDefender() {
        return new FormXssDefender(properties);
    }

}
