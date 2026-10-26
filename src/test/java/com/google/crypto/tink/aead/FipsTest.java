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

package com.google.crypto.tink.aead;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeFalse;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.aead.subtle.AesCtrHmacAead;
import com.google.crypto.tink.aead.subtle.AesEaxAead;
import com.google.crypto.tink.aead.subtle.AesGcmAead;
import com.google.crypto.tink.aead.subtle.AesGcmSivAead;
import com.google.crypto.tink.aead.subtle.ChaCha20Poly1305Aead;
import com.google.crypto.tink.aead.subtle.XAesGcmAead;
import com.google.crypto.tink.aead.subtle.XChaCha20Poly1305Aead;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.subtle.AesCtrJceCipher;
import com.google.crypto.tink.subtle.AesEaxJce;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.ChaCha20Poly1305;
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.crypto.tink.subtle.XChaCha20Poly1305;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for Aead which run under FIPS mode.
 *
 * <p>We test this by tagging the test with "fips" which runs it under three build configurations:
 *
 * <ul>
 *   <li>{@code
 *       //third_party/tink/java_src/src/main/java/com/google/crypto/tink/config:use_only_fips=False}
 *   <li>{@code
 *       //third_party/tink/java_src/src/main/java/com/google/crypto/tink/config:use_only_fips=True}
 *   <li>{@code
 *       //third_party/tink/java_src/src/main/java/com/google/crypto/tink/config:use_only_fips=True}
 *       and {@code BORINGSSL_FIPS=0} in C++.
 * </ul>
 */
@RunWith(JUnit4.class)
@LowLevelCryptoCaller
public final class FipsTest {

  @BeforeClass
  public static void setup() {
    if (TestUtil.isAndroid()) {
      return;
    }
    Conscrypt.checkAvailability();
    Security.addProvider(Conscrypt.newProvider());
  }

  @Test
  public void aeadConfig2026_aesCtrHmac() throws Exception {
    AesCtrHmacAeadParameters ctrHmacParams =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(32)
            .setTagSizeBytes(16)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
            .build();
    SecretBytes keyBytes16 = SecretBytes.copyFrom(new byte[16], InsecureSecretKeyAccess.get());
    SecretBytes keyBytes32 = SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get());
    KeysetHandle ctrHmacHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(
                        AesCtrHmacAeadKey.builder()
                            .setParameters(ctrHmacParams)
                            .setAesKeyBytes(keyBytes16)
                            .setHmacKeyBytes(keyBytes32)
                            .setIdRequirement(1234)
                            .build())
                    .withFixedId(1234)
                    .makePrimary())
            .build();

    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(ctrHmacParams, AeadConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> ctrHmacHandle.getPrimitive(AeadConfig2026.get(), Aead.class));
    } else {
      assertThat(KeysetHandle.generateNew(ctrHmacParams, AeadConfig2026.get())).isNotNull();
      assertThat(ctrHmacHandle.getPrimitive(AeadConfig2026.get(), Aead.class)).isNotNull();
    }
  }

  @Test
  public void aeadConfig2026_aesGcm() throws Exception {
    AesGcmParameters gcmParams =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.TINK)
            .build();
    SecretBytes keyBytes16 = SecretBytes.copyFrom(new byte[16], InsecureSecretKeyAccess.get());
    KeysetHandle gcmHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(
                        AesGcmKey.builder()
                            .setParameters(gcmParams)
                            .setKeyBytes(keyBytes16)
                            .setIdRequirement(1234)
                            .build())
                    .withFixedId(1234)
                    .makePrimary())
            .build();

    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(gcmParams, AeadConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> gcmHandle.getPrimitive(AeadConfig2026.get(), Aead.class));
    } else {
      assertThat(KeysetHandle.generateNew(gcmParams, AeadConfig2026.get())).isNotNull();
      assertThat(gcmHandle.getPrimitive(AeadConfig2026.get(), Aead.class)).isNotNull();
    }
  }

  @Test
  public void aeadConfig2026_aesGcmSiv() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    AesGcmSivParameters gcmSivParams =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(16)
            .setVariant(AesGcmSivParameters.Variant.TINK)
            .build();
    SecretBytes keyBytes16 = SecretBytes.copyFrom(new byte[16], InsecureSecretKeyAccess.get());
    KeysetHandle gcmSivHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(
                        AesGcmSivKey.builder()
                            .setParameters(gcmSivParams)
                            .setKeyBytes(keyBytes16)
                            .setIdRequirement(1234)
                            .build())
                    .withFixedId(1234)
                    .makePrimary())
            .build();

    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(gcmSivParams, AeadConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> gcmSivHandle.getPrimitive(AeadConfig2026.get(), Aead.class));
    } else {
      assertThat(KeysetHandle.generateNew(gcmSivParams, AeadConfig2026.get())).isNotNull();
      assertThat(gcmSivHandle.getPrimitive(AeadConfig2026.get(), Aead.class)).isNotNull();
    }
  }

  @Test
  public void aeadConfig2026_aesEax() throws Exception {
    AesEaxParameters eaxParams =
        AesEaxParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesEaxParameters.Variant.TINK)
            .build();
    SecretBytes keyBytes16 = SecretBytes.copyFrom(new byte[16], InsecureSecretKeyAccess.get());
    KeysetHandle eaxHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(
                        AesEaxKey.builder()
                            .setParameters(eaxParams)
                            .setKeyBytes(keyBytes16)
                            .setIdRequirement(1234)
                            .build())
                    .withFixedId(1234)
                    .makePrimary())
            .build();

    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(eaxParams, AeadConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> eaxHandle.getPrimitive(AeadConfig2026.get(), Aead.class));
    } else {
      assertThat(KeysetHandle.generateNew(eaxParams, AeadConfig2026.get())).isNotNull();
      assertThat(eaxHandle.getPrimitive(AeadConfig2026.get(), Aead.class)).isNotNull();
    }
  }

  @Test
  public void aeadConfig2026_chaCha20Poly1305() throws Exception {
    ChaCha20Poly1305Parameters chaChaParams =
        ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.TINK);
    SecretBytes keyBytes32 = SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get());
    KeysetHandle chaChaHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(
                        ChaCha20Poly1305Key.create(
                            ChaCha20Poly1305Parameters.Variant.TINK, keyBytes32, 1234))
                    .withFixedId(1234)
                    .makePrimary())
            .build();

    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(chaChaParams, AeadConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> chaChaHandle.getPrimitive(AeadConfig2026.get(), Aead.class));
    } else {
      assertThat(KeysetHandle.generateNew(chaChaParams, AeadConfig2026.get())).isNotNull();
      assertThat(chaChaHandle.getPrimitive(AeadConfig2026.get(), Aead.class)).isNotNull();
    }
  }

  @Test
  public void aeadConfig2026_xChaCha20Poly1305() throws Exception {
    XChaCha20Poly1305Parameters xChaChaParams =
        XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK);
    SecretBytes keyBytes32 = SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get());
    KeysetHandle xChaChaHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(
                        XChaCha20Poly1305Key.create(
                            XChaCha20Poly1305Parameters.Variant.TINK, keyBytes32, 1234))
                    .withFixedId(1234)
                    .makePrimary())
            .build();

    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(xChaChaParams, AeadConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> xChaChaHandle.getPrimitive(AeadConfig2026.get(), Aead.class));
    } else {
      assertThat(KeysetHandle.generateNew(xChaChaParams, AeadConfig2026.get())).isNotNull();
      assertThat(xChaChaHandle.getPrimitive(AeadConfig2026.get(), Aead.class)).isNotNull();
    }
  }

  @Test
  public void aeadConfig2026_xAesGcm() throws Exception {
    XAesGcmParameters xAesGcmParams = XAesGcmParameters.create(XAesGcmParameters.Variant.TINK, 12);
    SecretBytes keyBytes32 = SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get());
    KeysetHandle xAesGcmHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(XAesGcmKey.create(xAesGcmParams, keyBytes32, 1234))
                    .withFixedId(1234)
                    .makePrimary())
            .build();

    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(xAesGcmParams, AeadConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> xAesGcmHandle.getPrimitive(AeadConfig2026.get(), Aead.class));
    } else {
      assertThat(KeysetHandle.generateNew(xAesGcmParams, AeadConfig2026.get())).isNotNull();
      assertThat(xAesGcmHandle.getPrimitive(AeadConfig2026.get(), Aead.class)).isNotNull();
    }
  }

  @Test
  public void aesCtrHmacAeadCreate() throws Exception {
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.builder()
            .setParameters(
                AesCtrHmacAeadParameters.builder()
                    .setAesKeySizeBytes(16)
                    .setHmacKeySizeBytes(32)
                    .setTagSizeBytes(16)
                    .setIvSizeBytes(16)
                    .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                    .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
                    .build())
            .setAesKeyBytes(SecretBytes.copyFrom(new byte[16], InsecureSecretKeyAccess.get()))
            .setHmacKeyBytes(SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()))
            .setIdRequirement(1234)
            .build();
    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(GeneralSecurityException.class, () -> AesCtrHmacAead.create(key));
    } else {
      assertThat(AesCtrHmacAead.create(key)).isNotNull();
    }
  }

  @Test
  public void aesGcmAeadCreate() throws Exception {
    AesGcmKey key =
        AesGcmKey.builder()
            .setParameters(
                AesGcmParameters.builder()
                    .setKeySizeBytes(16)
                    .setIvSizeBytes(12)
                    .setTagSizeBytes(16)
                    .setVariant(AesGcmParameters.Variant.TINK)
                    .build())
            .setKeyBytes(SecretBytes.copyFrom(new byte[16], InsecureSecretKeyAccess.get()))
            .setIdRequirement(1234)
            .build();
    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(GeneralSecurityException.class, () -> AesGcmAead.create(key));
    } else {
      assertThat(AesGcmAead.create(key)).isNotNull();
    }
  }

  @Test
  public void aesGcmSivAeadCreate() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    AesGcmSivKey key =
        AesGcmSivKey.builder()
            .setParameters(
                AesGcmSivParameters.builder()
                    .setKeySizeBytes(16)
                    .setVariant(AesGcmSivParameters.Variant.TINK)
                    .build())
            .setKeyBytes(SecretBytes.copyFrom(new byte[16], InsecureSecretKeyAccess.get()))
            .setIdRequirement(1234)
            .build();
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> AesGcmSivAead.create(key));
    } else {
      assertThat(AesGcmSivAead.create(key)).isNotNull();
    }
  }

  @Test
  public void aesEaxAeadCreate() throws Exception {
    AesEaxKey key =
        AesEaxKey.builder()
            .setParameters(
                AesEaxParameters.builder()
                    .setKeySizeBytes(16)
                    .setIvSizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesEaxParameters.Variant.TINK)
                    .build())
            .setKeyBytes(SecretBytes.copyFrom(new byte[16], InsecureSecretKeyAccess.get()))
            .setIdRequirement(1234)
            .build();
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> AesEaxAead.create(key));
    } else {
      assertThat(AesEaxAead.create(key)).isNotNull();
    }
  }

  @Test
  public void chaCha20Poly1305AeadCreate() throws Exception {
    ChaCha20Poly1305Key key =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK,
            SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()),
            1234);
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> ChaCha20Poly1305Aead.create(key));
    } else {
      assertThat(ChaCha20Poly1305Aead.create(key)).isNotNull();
    }
  }

  @Test
  public void xChaCha20Poly1305AeadCreate() throws Exception {
    XChaCha20Poly1305Key key =
        XChaCha20Poly1305Key.create(
            XChaCha20Poly1305Parameters.Variant.TINK,
            SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()),
            1234);
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> XChaCha20Poly1305Aead.create(key));
    } else {
      assertThat(XChaCha20Poly1305Aead.create(key)).isNotNull();
    }
  }

  @Test
  public void xAesGcmAeadCreate() throws Exception {
    XAesGcmKey key =
        XAesGcmKey.create(
            XAesGcmParameters.create(XAesGcmParameters.Variant.TINK, 12),
            SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()),
            1234);
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> XAesGcmAead.create(key));
    } else {
      assertThat(XAesGcmAead.create(key)).isNotNull();
    }
  }

  @Test
  public void encryptThenAuthenticateCreate() throws Exception {
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.builder()
            .setParameters(
                AesCtrHmacAeadParameters.builder()
                    .setAesKeySizeBytes(16)
                    .setHmacKeySizeBytes(32)
                    .setTagSizeBytes(16)
                    .setIvSizeBytes(16)
                    .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                    .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
                    .build())
            .setAesKeyBytes(SecretBytes.copyFrom(new byte[16], InsecureSecretKeyAccess.get()))
            .setHmacKeyBytes(SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()))
            .setIdRequirement(1234)
            .build();
    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(GeneralSecurityException.class, () -> EncryptThenAuthenticate.create(key));
      assertThrows(
          GeneralSecurityException.class,
          () ->
              EncryptThenAuthenticate.newAesCtrHmac(
                  new byte[16], 16, "HMACSHA256", new byte[32], 16));
    } else {
      assertThat(EncryptThenAuthenticate.create(key)).isNotNull();
      assertThat(
              EncryptThenAuthenticate.newAesCtrHmac(
                  new byte[16], 16, "HMACSHA256", new byte[32], 16))
          .isNotNull();
    }
  }

  @Test
  public void aesCtrJceCipherConstructor() throws Exception {
    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(GeneralSecurityException.class, () -> new AesCtrJceCipher(new byte[16], 16));
    } else {
      assertThat(new AesCtrJceCipher(new byte[16], 16)).isNotNull();
    }
  }

  @Test
  public void aesGcmJceConstructorAndCreate() throws Exception {
    AesGcmKey key =
        AesGcmKey.builder()
            .setParameters(
                AesGcmParameters.builder()
                    .setKeySizeBytes(16)
                    .setIvSizeBytes(12)
                    .setTagSizeBytes(16)
                    .setVariant(AesGcmParameters.Variant.TINK)
                    .build())
            .setKeyBytes(SecretBytes.copyFrom(new byte[16], InsecureSecretKeyAccess.get()))
            .setIdRequirement(1234)
            .build();
    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(GeneralSecurityException.class, () -> new AesGcmJce(new byte[16]));
      assertThrows(GeneralSecurityException.class, () -> AesGcmJce.create(key));
    } else {
      assertThat(new AesGcmJce(new byte[16])).isNotNull();
      assertThat(AesGcmJce.create(key)).isNotNull();
    }
  }

  @Test
  public void aesEaxJceConstructorAndCreate() throws Exception {
    AesEaxKey key =
        AesEaxKey.builder()
            .setParameters(
                AesEaxParameters.builder()
                    .setKeySizeBytes(16)
                    .setIvSizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesEaxParameters.Variant.TINK)
                    .build())
            .setKeyBytes(SecretBytes.copyFrom(new byte[16], InsecureSecretKeyAccess.get()))
            .setIdRequirement(1234)
            .build();
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> new AesEaxJce(new byte[16], 16));
      assertThrows(GeneralSecurityException.class, () -> AesEaxJce.create(key));
    } else {
      assertThat(new AesEaxJce(new byte[16], 16)).isNotNull();
      assertThat(AesEaxJce.create(key)).isNotNull();
    }
  }

  @Test
  public void chaCha20Poly1305ConstructorAndCreate() throws Exception {
    ChaCha20Poly1305Key key =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK,
            SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()),
            1234);
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> new ChaCha20Poly1305(new byte[32]));
      assertThrows(GeneralSecurityException.class, () -> ChaCha20Poly1305.create(key));
    } else {
      assertThat(new ChaCha20Poly1305(new byte[32])).isNotNull();
      assertThat(ChaCha20Poly1305.create(key)).isNotNull();
    }
  }

  @Test
  public void xChaCha20Poly1305ConstructorAndCreate() throws Exception {
    XChaCha20Poly1305Key key =
        XChaCha20Poly1305Key.create(
            XChaCha20Poly1305Parameters.Variant.TINK,
            SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()),
            1234);
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> new XChaCha20Poly1305(new byte[32]));
      assertThrows(GeneralSecurityException.class, () -> XChaCha20Poly1305.create(key));
    } else {
      assertThat(new XChaCha20Poly1305(new byte[32])).isNotNull();
      assertThat(XChaCha20Poly1305.create(key)).isNotNull();
    }
  }
}
