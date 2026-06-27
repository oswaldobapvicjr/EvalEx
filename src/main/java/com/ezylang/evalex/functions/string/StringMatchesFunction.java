/*
  Copyright 2012-2024 Udo Klimaschewski

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/
package com.ezylang.evalex.functions.string;

import com.ezylang.evalex.EvaluationException;
import com.ezylang.evalex.Expression;
import com.ezylang.evalex.data.EvaluationValue;
import com.ezylang.evalex.functions.AbstractFunction;
import com.ezylang.evalex.functions.FunctionParameter;
import com.ezylang.evalex.parser.Token;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;

/**
 * Returns true if the string matches the pattern.
 *
 * <p><strong>Security:</strong> This function is protected against ReDoS (Regular Expression
 * Denial of Service) attacks through multiple layers of validation:
 *
 * <ul>
 *   <li><strong>Pattern length limit:</strong> Maximum 100 characters to prevent overly complex
 *       patterns
 *   <li><strong>Dangerous construct detection:</strong> Blocks known ReDoS patterns like (a+)+,
 *       (a*)*, etc.
 *   <li><strong>Regex execution timeout:</strong> 100ms timeout to catch unexpected patterns
 * </ul>
 *
 * @author HSGamer
 * @see <a href="https://github.com/ezylang/EvalEx/issues/570">Issue #570 - CWE-1333 ReDoS
 *     Vulnerability</a>
 */
@FunctionParameter(name = "string")
@FunctionParameter(name = "pattern")
public class StringMatchesFunction extends AbstractFunction {

  /**
   * Maximum allowed regex pattern length. Prevents excessively complex patterns that could cause
   * performance issues or ReDoS attacks.
   */
  private static final int MAX_PATTERN_LENGTH = 100;

  /**
   * Timeout in milliseconds for regex matching execution. Prevents catastrophic backtracking in
   * regex patterns from consuming excessive CPU resources.
   */
  private static final long REGEX_TIMEOUT_MS = 100;

  /**
   * Pattern to detect common ReDoS attack vectors. Matches nested quantifiers like (a+)+, (a*)*,
   * etc.
   */
  private static final Pattern REDOS_PATTERN =
      Pattern.compile("(\\([^)]*[+*][^)]*\\)[+*])|(\\[[^\\]]*\\][+*])");

  /**
   * Thread pool executor for executing regex matching with timeout. Shared across all invocations
   * to avoid excessive thread creation.
   */
  private static final ExecutorService EXECUTOR = Executors.newFixedThreadPool(2);

  @Override
  public EvaluationValue evaluate(
      Expression expression, Token functionToken, EvaluationValue... parameterValues)
      throws EvaluationException {
    String string = parameterValues[0].getStringValue();
    String pattern = parameterValues[1].getStringValue();

    // Layer 1: Validate pattern length to prevent overly complex patterns
    if (pattern.length() > MAX_PATTERN_LENGTH) {
      throw new EvaluationException(
          functionToken,
          String.format(
              "Regex pattern exceeds maximum length: %d > %d",
              pattern.length(), MAX_PATTERN_LENGTH));
    }

    // Layer 2: Detect and reject known ReDoS patterns
    if (REDOS_PATTERN.matcher(pattern).find()) {
      throw new EvaluationException(
          functionToken,
          "Regex pattern contains potentially dangerous constructs that could cause ReDoS");
    }

    // Layer 3: Execute regex matching with timeout to catch unexpected ReDoS patterns
    try {
      Future<Boolean> future = EXECUTOR.submit(() -> string.matches(pattern));
      return expression.convertValue(future.get(REGEX_TIMEOUT_MS, TimeUnit.MILLISECONDS));
    } catch (TimeoutException e) {
      throw new EvaluationException(
          functionToken,
          "Regex matching timed out - pattern may be vulnerable to ReDoS attack");
    } catch (EvaluationException e) {
      // Re-throw EvaluationException as-is
      throw e;
    } catch (Exception e) {
      // Catch all other exceptions (InterruptedException, ExecutionException, etc.)
      if (e.getCause() instanceof java.util.regex.PatternSyntaxException) {
        throw new EvaluationException(
            functionToken, "Invalid regex pattern: " + e.getCause().getMessage());
      }
      throw new EvaluationException(functionToken, "Regex matching failed: " + e.getMessage());
    }
  }
}
