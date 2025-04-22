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

package com.google.crypto.tink.config;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.HashSet;
import java.util.Set;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class GlobalTinkFlagsTest {
  // This should contain a list of all the flag names GlobalTinkFlags currently has.
  private static Set<String> expectedFlagNames() {
    Set<String> result = new HashSet<>();
    result.add("validateKeysetsOnParsing");
    return result;
  }

  private static Set<Field> getPublicFields(Class<?> clazz) {
    Set<Field> result = new HashSet<>();
    Field[] fields = clazz.getDeclaredFields();
    for (Field field : fields) {
      if (Modifier.isPublic(field.getModifiers())) {
        result.add(field);
      }
    }
    return result;
  }

  /** This test ensures that we only add public static fields. */
  @Test
  public void allPublicFieldsAreStaticTinkFlags() {
    for (Field field : getPublicFields(GlobalTinkFlags.class)) {
      assertTrue(Modifier.isStatic(field.getModifiers()));
      assertThat(field.getType()).isEqualTo(TinkFlag.class);
    }
  }

  /**
   * This test ensures that the flag names are as in "expectedFlagNames". This is an important test
   * because within Google we have two implementations of GlobalTinkFlags, and this test helps to
   * keep them in sync.
   */
  @Test
  public void flagNamesAreAsExpected() {
    Set<String> presentFlagNames = new HashSet<>();
    for (Field field : getPublicFields(GlobalTinkFlags.class)) {
      presentFlagNames.add(field.getName());
    }
    assertThat(presentFlagNames).isEqualTo(expectedFlagNames());
  }
}
