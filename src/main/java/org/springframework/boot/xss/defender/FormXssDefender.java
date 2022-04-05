package org.springframework.boot.xss.defender;

import org.springframework.boot.xss.defender.autoconfigure.XssDefenderProperties;
import org.springframework.web.bind.WebDataBinder;
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
 * @see DefaultXssDefender
 * @see PropertyEditorSupport
 * @see StringXssPropertyEditor
 * @see WebDataBinder#registerCustomEditor(Class, PropertyEditor)
 * @since 1.0.0
 */
public class FormXssDefender extends DefaultXssDefender {

    /**
     * A properties object for spring boot auto configuration.
     */
    private final XssDefenderProperties properties;

    public FormXssDefender(XssDefenderProperties properties) {
        this.properties = properties;
    }

    @InitBinder
    public void initBinder(WebDataBinder binder) {
        binder.registerCustomEditor(String.class, new StringXssPropertyEditor(this, properties));
    }

    /**
     * A custom implementation of {@link PropertyEditor} for the parameter's secondary processing.
     *
     * @see FormXssDefender
     */
    private static class StringXssPropertyEditor extends PropertyEditorSupport {

        /**
         * The instance of {@link DefaultXssDefender}
         */
        private final DefaultXssDefender defender;

        /**
         * A properties object for spring boot auto configuration.
         */
        private final XssDefenderProperties properties;

        private StringXssPropertyEditor(DefaultXssDefender defender, XssDefenderProperties properties) {
            this.defender = defender;
            this.properties = properties;
        }

        @Override
        public void setAsText(String text) throws IllegalArgumentException {
            final String safeText = defender.defend(properties, text);
            super.setAsText(safeText);
        }

    }

}
