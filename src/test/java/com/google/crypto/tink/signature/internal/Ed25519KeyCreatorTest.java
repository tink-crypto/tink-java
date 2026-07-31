// Copyright 2026 Google LLC
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

package com.google.crypto.tink.signature.internal;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.signature.Ed25519Parameters;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Ed25519KeyCreator}. */
@RunWith(JUnit4.class)
public final class Ed25519KeyCreatorTest {

  @Test
  public void createKey_tink_works() throws Exception {
    Ed25519Parameters parameters = Ed25519Parameters.create(Ed25519Parameters.Variant.TINK);
    Ed25519PrivateKey key = Ed25519KeyCreator.createKey(parameters, /* idRequirement= */ 123);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(123);
    assertThat(key.getOutputPrefix()).isNotNull();
    assertThat(key.getPrivateKeyBytes()).isNotNull();
  }

  @Test
  public void createKey_raw_works() throws Exception {
    Ed25519Parameters parameters = Ed25519Parameters.create(Ed25519Parameters.Variant.NO_PREFIX);
    Ed25519PrivateKey key = Ed25519KeyCreator.createKey(parameters, /* idRequirement= */ null);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isNull();
    assertThat(key.getPrivateKeyBytes()).isNotNull();
  }

  @Test
  public void createKey_calledTwice_createsDifferentKeys() throws Exception {
    Ed25519Parameters parameters = Ed25519Parameters.create(Ed25519Parameters.Variant.TINK);
    Ed25519PrivateKey key0 = Ed25519KeyCreator.createKey(parameters, /* idRequirement= */ 123);
    Ed25519PrivateKey key1 = Ed25519KeyCreator.createKey(parameters, /* idRequirement= */ 123);

    assertThat(key0.equalsKey(key1)).isFalse();
  }
}
