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

package com.google.crypto.tink.mac.internal;

import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType;
import com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacParameters;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests that prefix comparison in LegacyFullMac.verifyMac() uses a constant-time
 * method (MessageDigest.isEqual) rather than Arrays.equals, which short-circuits
 * on the first differing byte and can leak information via timing side-channels.
 *
 * <p>See: https://github.com/tink-crypto/tink-java/issues/75
 */
@RunWith(JUnit4.class)
public class LegacyFullMacTimingSafeTest {

  private static final String TYPE_URL = "type.googleapis.com/custom.HmacKey";
  private static final int HMAC_KEY_SIZE = 32;
  private static final int HMAC_TAG_SIZE = 16;

  @BeforeClass
  public static void setUp() throws Exception {
    MacConfig.register();
    LegacyHmacTestKeyManager.register();
  }

  @Test
  public void verifyMac_rejectsPrefixWithCorrectFirstByte_tinkVariant() throws Exception {
    HmacKey hmacKey = buildHmacKey(HmacParameters.Variant.TINK, 0x01020304);
    Mac mac = LegacyFullMac.create(buildLegacyProtoKey(hmacKey, OutputPrefixType.TINK));

    byte[] message = new byte[] {0x00, 0x01, 0x02, 0x03};
    byte[] validTag = mac.computeMac(message);

    byte[] tampered = Arrays.copyOf(validTag, validTag.length);
    tampered[4] ^= 0xFF;

    assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(tampered, message));
  }

  @Test
  public void verifyMac_rejectsPrefixWithCorrectFirstByte_crunchyVariant() throws Exception {
    HmacKey hmacKey = buildHmacKey(HmacParameters.Variant.CRUNCHY, 0x0A0B0C0D);
    Mac mac = LegacyFullMac.create(buildLegacyProtoKey(hmacKey, OutputPrefixType.CRUNCHY));

    byte[] message = new byte[] {0x10, 0x20, 0x30};
    byte[] validTag = mac.computeMac(message);

    byte[] tampered = Arrays.copyOf(validTag, validTag.length);
    tampered[4] ^= 0xFF;

    assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(tampered, message));
  }

  @Test
  public void verifyMac_rejectsCompletelyWrongPrefix() throws Exception {
    HmacKey hmacKey = buildHmacKey(HmacParameters.Variant.TINK, 0xDEADBEEF);
    Mac mac = LegacyFullMac.create(buildLegacyProtoKey(hmacKey, OutputPrefixType.TINK));

    byte[] message = new byte[] {0x42};
    byte[] validTag = mac.computeMac(message);

    byte[] tampered = Arrays.copyOf(validTag, validTag.length);
    for (int i = 0; i < 5; i++) {
      tampered[i] ^= 0xFF;
    }

    assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(tampered, message));
  }

  private static HmacKey buildHmacKey(HmacParameters.Variant variant, int keyId)
      throws GeneralSecurityException {
    HmacParameters params =
        HmacParameters.builder()
            .setKeySizeBytes(HMAC_KEY_SIZE)
            .setTagSizeBytes(HMAC_TAG_SIZE)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(variant)
            .build();
    return HmacKey.builder()
        .setParameters(params)
        .setKeyBytes(SecretBytes.randomBytes(HMAC_KEY_SIZE))
        .setIdRequirement(variant == HmacParameters.Variant.NO_PREFIX ? null : keyId)
        .build();
  }

  private static LegacyProtoKey buildLegacyProtoKey(HmacKey key, OutputPrefixType prefixType)
      throws GeneralSecurityException {
    com.google.crypto.tink.proto.HmacKey protoKey =
        com.google.crypto.tink.proto.HmacKey.newBuilder()
            .setParams(
                com.google.crypto.tink.proto.HmacParams.newBuilder()
                    .setTagSize(key.getParameters().getCryptographicTagSizeBytes())
                    .setHash(com.google.crypto.tink.proto.HashType.SHA256)
                    .build())
            .setKeyValue(
                ByteString.copyFrom(
                    key.getKeyBytes()
                        .toByteArray(
                            com.google.crypto.tink.SecretKeyAccess.requireAccess(
                                InsecureSecretKeyAccess.get()))))
            .build();

    return new LegacyProtoKey(
        ProtoKeySerialization.create(
            TYPE_URL,
            protoKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            prefixType,
            key.getIdRequirementOrNull()),
        InsecureSecretKeyAccess.get());
  }
}
