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

package com.google.crypto.tink.prf;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.prf.internal.AesCmacPrfProtoSerialization;
import com.google.crypto.tink.prf.internal.HkdfPrfProtoSerialization;
import com.google.crypto.tink.prf.internal.HmacPrfProtoSerialization;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class PrfConfiguration2026Test {
  @Test
  public void config_throwsIfInFipsMode() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());

    assertThrows(GeneralSecurityException.class, PrfConfiguration2026::get);
  }

  @Test
  public void config_containsHmacPrf() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    HmacPrfProtoSerialization.register();

    HmacPrfKey key =
        HmacPrfKey.builder()
            .setParameters(
                HmacPrfParameters.builder()
                    .setKeySizeBytes(32)
                    .setHashType(HmacPrfParameters.HashType.SHA512)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(PrfConfiguration2026.get(), PrfSet.class)).isNotNull();
  }

  @Test
  public void config_containsHkdfPrf() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    HkdfPrfProtoSerialization.register();

    HkdfPrfKey key =
        HkdfPrfKey.builder()
            .setParameters(
                HkdfPrfParameters.builder()
                    .setKeySizeBytes(32)
                    .setHashType(HkdfPrfParameters.HashType.SHA256)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(PrfConfiguration2026.get(), PrfSet.class)).isNotNull();
  }

  @Test
  public void config_containsAesCmacPrf() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    AesCmacPrfProtoSerialization.register();

    AesCmacPrfKey key =
        AesCmacPrfKey.create(AesCmacPrfParameters.create(32), SecretBytes.randomBytes(32));
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(PrfConfiguration2026.get(), PrfSet.class)).isNotNull();
  }

  @Test
  public void wrongAesCmacPrfKeySize_throws() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    AesCmacPrfProtoSerialization.register();

    AesCmacPrfKey key =
        AesCmacPrfKey.create(AesCmacPrfParameters.create(16), SecretBytes.randomBytes(16));
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(PrfConfiguration2026.get(), PrfSet.class));
  }
  @Test
  public void wrongHkdfPrfKeySize_throws() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    HkdfPrfProtoSerialization.register();

    HkdfPrfKey key =
        HkdfPrfKey.builder()
            .setParameters(
                HkdfPrfParameters.builder()
                    .setKeySizeBytes(16)
                    .setHashType(HkdfPrfParameters.HashType.SHA256)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(16))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    Configuration config = PrfConfiguration2026.get();
    assertThrows(
        GeneralSecurityException.class, () -> keysetHandle.getPrimitive(config, PrfSet.class));
  }

  @Test
  public void wrongHkdfPrfHashFunction_throws() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    HkdfPrfProtoSerialization.register();

    HkdfPrfKey key =
        HkdfPrfKey.builder()
            .setParameters(
                HkdfPrfParameters.builder()
                    .setKeySizeBytes(32)
                    .setHashType(HkdfPrfParameters.HashType.SHA1)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    Configuration configuration = PrfConfiguration2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(configuration, PrfSet.class));
  }

  @Test
  public void createKey_hmacPrfParameters() throws Exception {
    HmacPrfParameters parameters =
        HmacPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HmacPrfParameters.HashType.SHA256)
            .build();
    Key key = PrfConfiguration2026.get().createKey(parameters, null);
    assertThat(key).isInstanceOf(HmacPrfKey.class);
    HmacPrfKey hmacPrfKey = (HmacPrfKey) key;
    assertThat(hmacPrfKey.getParameters()).isEqualTo(parameters);
  }

  @Test
  public void createKey_hkdfPrfParameters() throws Exception {
    HkdfPrfParameters parameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .build();
    Key key = PrfConfiguration2026.get().createKey(parameters, null);
    assertThat(key).isInstanceOf(HkdfPrfKey.class);
    HkdfPrfKey hkdfPrfKey = (HkdfPrfKey) key;
    assertThat(hkdfPrfKey.getParameters()).isEqualTo(parameters);
  }

  @Test
  public void createKey_aesCmacPrfParameters() throws Exception {
    AesCmacPrfParameters parameters = AesCmacPrfParameters.create(32);
    Key key = PrfConfiguration2026.get().createKey(parameters, null);
    assertThat(key).isInstanceOf(AesCmacPrfKey.class);
    AesCmacPrfKey aesCmacPrfKey = (AesCmacPrfKey) key;
    assertThat(aesCmacPrfKey.getParameters()).isEqualTo(parameters);
  }

  @Test
  public void createKey_idRequirementNonNull_throws() throws Exception {
    HkdfPrfParameters parameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .build();
    Configuration config = PrfConfiguration2026.get();
    assertThrows(GeneralSecurityException.class, () -> config.createKey(parameters, 123));
  }

  @Test
  public void createKey_unrecognizedParameters_throws() throws Exception {
    Parameters parameters =
        new Parameters() {
          @Override
          public boolean hasIdRequirement() {
            return false;
          }
        };
    Configuration config = PrfConfiguration2026.get();
    assertThrows(GeneralSecurityException.class, () -> config.createKey(parameters, null));
  }

  private static interface DummyPrimitive {}

  @Test
  public void createPrimitive_unsupportedPrimitiveClass_throws() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    HmacPrfProtoSerialization.register();
    HmacPrfParameters parameters =
        HmacPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HmacPrfParameters.HashType.SHA256)
            .build();
    HmacPrfKey key =
        HmacPrfKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    Configuration config = PrfConfiguration2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(config, DummyPrimitive.class));
  }
}
