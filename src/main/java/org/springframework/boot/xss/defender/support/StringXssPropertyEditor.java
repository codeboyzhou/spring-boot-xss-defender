package org.springframework.boot.xss.defender.support;

import org.springframework.boot.xss.defender.XssDefender;
import org.springframework.boot.xss.defender.autoconfigure.XssDefenderConfiguration;
import org.springframework.util.StringUtils;
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
 * @see XssDefender
 * @see PropertyEditorSupport
 * @see XssDefenderConfiguration
 * @see WebDataBinder#registerCustomEditor(Class, PropertyEditor)
 * @since 1.0.0
 */
public class StringXssPropertyEditor extends PropertyEditorSupport {

    /**
     * Whether the XSS defender is enabled.
     */
    private final boolean isXssDefenderEnabled;

    /**
     * An instance of {@link XssDefender}
     */
    private final XssDefender xssDefender;

    public StringXssPropertyEditor(boolean isXssDefenderEnabled, XssDefender xssDefender) {
        this.isXssDefenderEnabled = isXssDefenderEnabled;
        this.xssDefender = xssDefender;
    }

    @Override
    public void setValue(Object value) {
        super.setValue(value == null ? XssDefender.EMPTY_STRING : value);
    }

    @Override
    public void setAsText(String text) throws IllegalArgumentException {
        final String safeText = isXssDefenderEnabled ? xssDefender.defend(text) : StringUtils.trimWhitespace(text);
        super.setAsText(safeText);
    }

}
