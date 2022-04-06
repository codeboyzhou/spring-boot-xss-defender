package org.springframework.boot.xss.defender;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.xss.defender.autoconfigure.XssDefenderProperties;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.InitBinder;

import java.beans.PropertyEditor;
import java.beans.PropertyEditorSupport;

/**
 * This class is intended to process the XSS risk from html FORM parameters.
 * With the help of {@link WebDataBinder} from spring framework, we can use
 * the annotation {@link InitBinder} to register a custom {@link PropertyEditor}
 * for the parameter's secondary processing, so as to get rid of the potential XSS risk.
 *
 * @author codeboyzhou
 * @see XssDefender
 * @see PropertyEditorSupport
 * @see StringXssPropertyEditor
 * @see WebDataBinder#registerCustomEditor(Class, PropertyEditor)
 * @since 1.0.0
 */
@ControllerAdvice
public class FormXssDefender implements XssDefender {

    private static final Logger logger = LoggerFactory.getLogger(FormXssDefender.class);

    /**
     * A properties object for spring boot auto configuration.
     */
    private final XssDefenderProperties properties;

    public FormXssDefender(XssDefenderProperties properties) {
        if (logger.isInfoEnabled()) {
            logger.info("Registered java bean: {}", FormXssDefender.class);
        }
        this.properties = properties;
    }

    /**
     * NOTICE: {@link FormXssDefender} must have annotation {@link ControllerAdvice} to guarantee {@link InitBinder} does work globally.
     */
    @InitBinder
    public void initBinder(WebDataBinder binder) {
        if (logger.isDebugEnabled()) {
            logger.debug("Initializing WebDataBinder, register custom property editor: {}", StringXssPropertyEditor.class);
        }
        binder.registerCustomEditor(String.class, new StringXssPropertyEditor(this, properties));
    }

    /**
     * An inner class, custom implementation of {@link PropertyEditor} for the parameter's secondary processing.
     *
     * @see FormXssDefender
     */
    private static class StringXssPropertyEditor extends PropertyEditorSupport {

        /**
         * The instance of {@link XssDefender}
         */
        private final XssDefender defender;

        /**
         * A properties object for spring boot auto configuration.
         */
        private final XssDefenderProperties properties;

        private StringXssPropertyEditor(XssDefender defender, XssDefenderProperties properties) {
            this.defender = defender;
            this.properties = properties;
        }

        @Override
        public void setValue(Object value) {
            super.setValue(value == null ? EMPTY_STRING : value);
        }

        @Override
        public void setAsText(String text) throws IllegalArgumentException {
            final String safeText = properties.isEnabled() ? defender.defend(properties, text) : StringUtils.trimWhitespace(text);
            super.setAsText(safeText);
        }

    }

}
