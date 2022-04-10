package org.springframework.boot.xss.defender;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.xss.defender.exception.UnsupportedXssDefenseStrategyException;
import org.springframework.boot.xss.defender.exception.XssRiskDetectedException;

/**
 * Junit test for {@link XssDefender}
 *
 * @author codeboyzhou
 * @since 1.0.0
 */
class XssDefenderTest {

    static final String SPACE_STRING = " ";

    @Test
    void defendWhenInputTextIsInvalid() {
        XssDefender anyXssDefender = new XssDefender(Mockito.any(), Mockito.anyBoolean());
        final String resultIfInputNull = anyXssDefender.defend(null);
        Assertions.assertEquals(XssDefender.EMPTY_STRING, resultIfInputNull);
        final String resultIfInputEmpty = anyXssDefender.defend(XssDefender.EMPTY_STRING);
        Assertions.assertEquals(XssDefender.EMPTY_STRING, resultIfInputEmpty);
        final String resultIfInputWhitespace = anyXssDefender.defend(SPACE_STRING);
        Assertions.assertEquals(XssDefender.EMPTY_STRING, resultIfInputWhitespace);
    }

    @Test
    void defendWhenDefenseStrategyIsTrim() {
        XssDefender xssDefenderTrim = new XssDefender(DefenseStrategy.TRIM.name(), Mockito.anyBoolean());
        final String resultIfTrimAll = xssDefenderTrim.defend("<script>alert(document.cookies);</script>");
        Assertions.assertEquals(XssDefender.EMPTY_STRING, resultIfTrimAll);
        final String resultIfTrimPartial = xssDefenderTrim.defend("XssDefenderTest<script>alert(document.cookies);</script>");
        Assertions.assertEquals("XssDefenderTest", resultIfTrimPartial);
    }

    @Test
    void defendWhenDefenseStrategyIsTrimAndEscape() {
        XssDefender xssDefenderTrimAndEscape = new XssDefender(DefenseStrategy.TRIM.name(), true);
        final String result = xssDefenderTrimAndEscape.defend("<code>XssDefenderTest</code><script>alert(document.cookies);</script>");
        Assertions.assertEquals("&lt;code&gt;XssDefenderTest&lt;/code&gt;", result);
    }

    @Test
    void defendWhenDefenseStrategyIsEscape() {
        XssDefender xssDefenderEscape = new XssDefender(DefenseStrategy.ESCAPE.name(), Mockito.anyBoolean());
        final String result = xssDefenderEscape.defend("<script>alert(document.cookies);</script>");
        Assertions.assertEquals("&lt;script&gt;alert(document.cookies);&lt;/script&gt;", result);
    }

    @Test
    void defendWhenDefenseStrategyIsThrow() {
        XssDefender xssDefenderThrow = new XssDefender(DefenseStrategy.THROW.name(), Mockito.anyBoolean());
        final String testXssText = "<script>alert(document.cookies);</script>";
        Assertions.assertThrowsExactly(XssRiskDetectedException.class, () -> xssDefenderThrow.defend(testXssText), testXssText);
        final String testNormalText = "XssDefenderTest";
        Assertions.assertDoesNotThrow(() -> xssDefenderThrow.defend(testNormalText));
    }

    @Test
    void defendWhenDefenseStrategyNotSupported() {
        final String str = "ignore";
        XssDefender unsupportedStrategy = new XssDefender(str, Mockito.anyBoolean());
        Assertions.assertThrowsExactly(UnsupportedXssDefenseStrategyException.class, () -> unsupportedStrategy.defend(str), str);
    }

}