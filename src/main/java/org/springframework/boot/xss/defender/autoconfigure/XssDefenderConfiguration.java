package org.springframework.boot.xss.defender.autoconfigure;

import com.fasterxml.jackson.databind.JsonDeserializer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.xss.defender.XssDefender;
import org.springframework.boot.xss.defender.interceptor.XssDefenderInterceptor;
import org.springframework.boot.xss.defender.support.StringXssJsonDeserializer;
import org.springframework.boot.xss.defender.support.StringXssPropertyEditor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.core.Ordered;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.beans.PropertyEditor;

/**
 * Add some auto configuration, for example, register interceptors, and some essential java beans.
 *
 * @author codeboyzhou
 * @see XssDefenderProperties
 * @see XssDefenderInterceptor
 * @since 1.0.0
 */
@ComponentScan(basePackageClasses = XssDefender.class)
@EnableConfigurationProperties(XssDefenderProperties.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = XssDefenderProperties.PREFIX, name = "enabled", havingValue = "true", matchIfMissing = true)
public class XssDefenderConfiguration implements WebMvcConfigurer {

    /**
     * Let spring web container load interceptor.
     */
    @Autowired
    private XssDefenderInterceptor interceptor;

    /**
     * A properties object for spring boot auto configuration.
     */
    private XssDefenderProperties properties;

    /**
     * An instance of {@link XssDefender}
     */
    private XssDefender xssDefender;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(interceptor).order(Ordered.LOWEST_PRECEDENCE);
    }

    @Bean
    public XssDefender xssDefender() {
        return new XssDefender(properties.getStrategy(), properties.isEscapeAfterTrimEnabled());
    }

    /**
     * Customize a property editor for html FORM parameter, so as to process potential XSS risk in the parameter.
     */
    @InitBinder
    public void initBinder(WebDataBinder binder) {
        PropertyEditor customPropertyEditor = new StringXssPropertyEditor(properties.isEnabled(), xssDefender);
        binder.registerCustomEditor(String.class, customPropertyEditor);
    }

    /**
     * Customize a deserializer for JSON parameter, so as to process potential XSS risk in the parameter.
     */
    @Bean
    public Jackson2ObjectMapperBuilderCustomizer xssDefenderJacksonCustomizer() {
        JsonDeserializer<String> customJsonDeserializer = new StringXssJsonDeserializer(properties.isEnabled(), xssDefender);
        return builder -> builder.deserializerByType(String.class, customJsonDeserializer);
    }

}
