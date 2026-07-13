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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.ChaCha20Poly1305Key;
import com.google.crypto.tink.aead.ChaCha20Poly1305Parameters;
import com.google.crypto.tink.aead.XChaCha20Poly1305Key;
import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class ProtoBasedConfigurationBuilderTest {
  @Test
  public void testBuildEmpty_works() throws Exception {
    Configuration config = new ProtoBasedConfigurationBuilder().build();
    assertThat(config).isNotNull();
  }

  @Test
  public void testCreateKey_withoutIdRequirement_works() throws Exception {
    Configuration config =
        new ProtoBasedConfigurationBuilder()
            .addKeyCreator(
                XChaCha20Poly1305Parameters.class,
                (p, id) ->
                    XChaCha20Poly1305Key.create(p.getVariant(), SecretBytes.randomBytes(32), id))
            .build();

    // Create without id Requirement works
    Key createdKey = config.createKey(XChaCha20Poly1305Parameters.create(), null);
    assertThat(createdKey.getParameters()).isEqualTo(XChaCha20Poly1305Parameters.create());

    // Create with id Requirement works
    Parameters tinkParams =
        XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK);
    createdKey = config.createKey(tinkParams, 13996);
    assertThat(createdKey.getParameters()).isEqualTo(tinkParams);
    assertThat(createdKey.getIdRequirementOrNull()).isEqualTo(13996);

    // If idRequirement is wrong we throw.
    assertThrows(
        GeneralSecurityException.class,
        () -> config.createKey(XChaCha20Poly1305Parameters.create(), 1234));
    assertThrows(GeneralSecurityException.class, () -> config.createKey(tinkParams, null));
  }

  @Test
  public void testAddKeyCreator_twiceForSameParameters_throws() throws Exception {
    ProtoBasedConfigurationBuilder builder =
        new ProtoBasedConfigurationBuilder()
            .addKeyCreator(
                XChaCha20Poly1305Parameters.class,
                (p, id) ->
                    XChaCha20Poly1305Key.create(p.getVariant(), SecretBytes.randomBytes(32), id));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            builder.addKeyCreator(
                XChaCha20Poly1305Parameters.class,
                (p, id) ->
                    XChaCha20Poly1305Key.create(p.getVariant(), SecretBytes.randomBytes(32), id)));
  }

  @Test
  public void testDispatchToMultipleCreators_works() throws Exception {
    Configuration config =
        new ProtoBasedConfigurationBuilder()
            .addKeyCreator(
                XChaCha20Poly1305Parameters.class,
                (p, id) ->
                    XChaCha20Poly1305Key.create(p.getVariant(), SecretBytes.randomBytes(32), id))
            .addKeyCreator(
                ChaCha20Poly1305Parameters.class,
                (p, id) ->
                    ChaCha20Poly1305Key.create(p.getVariant(), SecretBytes.randomBytes(32), id))
            .build();

    Key creator1Key = config.createKey(XChaCha20Poly1305Parameters.create(), null);
    assertThat(creator1Key.getParameters()).isEqualTo(XChaCha20Poly1305Parameters.create());

    Key creator2Key = config.createKey(ChaCha20Poly1305Parameters.create(), null);
    assertThat(creator2Key.getParameters()).isEqualTo(ChaCha20Poly1305Parameters.create());
  }
}
