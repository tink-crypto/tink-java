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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.config.TinkFlag;
import java.security.GeneralSecurityException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class SetTinkFlagTest {
  public static class MyTinkFlag implements TinkFlag {
    boolean b;

    MyTinkFlag(boolean b) {
      this.b = b;
    }

    @Override
    public void setValue(boolean t) {
      b = t;
    }

    @Override
    public boolean getValue() {
      return b;
    }
  }

  @Rule public SetTinkFlag setFlag = new SetTinkFlag();

  @SuppressWarnings("NonFinalStaticField") // That's the whole point of this test.
  public static TinkFlag trueFlag = new MyTinkFlag(true);

  @SuppressWarnings("NonFinalStaticField")
  public static TinkFlag falseFlag = new MyTinkFlag(false);

  @Test
  public void setTrueFlag() throws Exception {
    assertThat(trueFlag.getValue()).isEqualTo(true);
    assertThat(falseFlag.getValue()).isEqualTo(false);
    setFlag.untilTheEndOfThisTest(trueFlag, false);

    assertThat(trueFlag.getValue()).isEqualTo(false);
  }

  @Test
  public void setFalseFlag() throws Exception {
    assertThat(trueFlag.getValue()).isEqualTo(true);
    assertThat(falseFlag.getValue()).isEqualTo(false);
    setFlag.untilTheEndOfThisTest(falseFlag, true);

    assertThat(falseFlag.getValue()).isEqualTo(true);
  }

  @Test
  public void setTrueFlag_toTrue_doesNothing() throws Exception {
    assertThat(trueFlag.getValue()).isEqualTo(true);
    assertThat(falseFlag.getValue()).isEqualTo(false);
    setFlag.untilTheEndOfThisTest(trueFlag, true);

    assertThat(trueFlag.getValue()).isEqualTo(true);
  }

  @Test
  public void setFalseFlag_toFalse_doesNothing() throws Exception {
    assertThat(trueFlag.getValue()).isEqualTo(true);
    assertThat(falseFlag.getValue()).isEqualTo(false);
    setFlag.untilTheEndOfThisTest(falseFlag, false);

    assertThat(falseFlag.getValue()).isEqualTo(false);
  }

  @Test
  public void setFlagTwice_throws() throws Exception {
    assertThat(trueFlag.getValue()).isEqualTo(true);
    assertThat(falseFlag.getValue()).isEqualTo(false);
    setFlag.untilTheEndOfThisTest(falseFlag, true);
    assertThrows(
        GeneralSecurityException.class, () -> setFlag.untilTheEndOfThisTest(falseFlag, false));

    assertThat(falseFlag.getValue()).isEqualTo(true);
  }
}
