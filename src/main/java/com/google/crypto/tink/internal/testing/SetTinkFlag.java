// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.internal.testing;

import com.google.crypto.tink.config.TinkFlag;
import java.security.GeneralSecurityException;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

/**
 * A junit rule which sets a TinkFlag back to it's original value.
 *
 * <p>Junit offers the concept of {@link org.junit.rules.Rule}, which are (similar to Python
 * decorators) functions which transform a test function into another test function. We use this to
 * set a TinkFlag until a test is done, at which point we reset the TinkFlag to its original value.
 */
public final class SetTinkFlag implements TestRule {

  private TinkFlag flag = null;
  private boolean initialValue = false;

  public void untilTheEndOfThisTest(TinkFlag flag, boolean value) throws GeneralSecurityException {
    // Guava Flags need this to change Guava flags; we do it here simply because we know we are in
    // test code and the user wants to change a flag.
    BuildDispatchedTestCode.disableFlagsStateCheckingForTests();
    if (this.flag != null) {
      throw new GeneralSecurityException(
          "SetTinkFlag currently only suppors a single call to untilTheEndOfThisTest.");
    }
    initialValue = flag.getValue();
    flag.setValue(value);
    this.flag = flag;
  }

  @Override
  public Statement apply(final Statement base, Description description) {
    return new Statement() {
      @Override
      public void evaluate() throws Throwable {
        try {
          base.evaluate();
        } finally {
          if (flag != null) {
            flag.setValue(initialValue);
            flag = null;
          }
        }
      }
    };
  }
}
