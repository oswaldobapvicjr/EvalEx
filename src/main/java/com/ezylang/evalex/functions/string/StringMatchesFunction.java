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
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Returns true if the string matches the pattern.
 *
 * <p><strong>Security:</strong> Since 3.6.3, this function applies a execution timeout defined by
 * configuration property 'regexTimeoutMillis' to prevent ReDoS (Regular Expression Denial of
 * Service).
 *
 * @author HSGamer
 * @see <a href="https://github.com/ezylang/EvalEx/issues/570">Issue #570 - CWE-1333 ReDoS
 *     Vulnerability</a>
 */
@FunctionParameter(name = "string")
@FunctionParameter(name = "pattern")
public class StringMatchesFunction extends AbstractFunction {

  /**
   * Thread pool executor for executing regex matching with timeout. Shared across all invocations
   * to avoid excessive thread creation.
   */
  private static final ExecutorService EXECUTOR = Executors.newFixedThreadPool(10);

  @Override
  public EvaluationValue evaluate(
      Expression expression, Token functionToken, EvaluationValue... parameterValues)
      throws EvaluationException {
    String string = parameterValues[0].getStringValue();
    String pattern = parameterValues[1].getStringValue();

    // Execute regex matching with timeout to catch unexpected ReDoS patterns
    long regexTimeoutMillis = expression.getConfiguration().getRegexTimeoutMillis();
    try {
      Future<Boolean> future = EXECUTOR.submit(() -> string.matches(pattern));
      return expression.convertValue(future.get(regexTimeoutMillis, TimeUnit.MILLISECONDS));
    } catch (TimeoutException e) {
      throw new EvaluationException(functionToken, "Regex matching timed out");
    } catch (ExecutionException e) {
      throw new EvaluationException(
          functionToken, "Invalid regex pattern: " + e.getCause().getMessage());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new EvaluationException(functionToken, "Interrupted while matching");
    }
  }
}
