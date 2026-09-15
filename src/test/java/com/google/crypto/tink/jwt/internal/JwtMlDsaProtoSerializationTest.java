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

package com.google.crypto.tink.jwt.internal;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.testing.Asserts.assertEqualWhenValueParsed;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType;
import com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType;
import com.google.crypto.tink.ProtoParametersSerialization;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.jwt.JwtMlDsaParameters;
import com.google.crypto.tink.jwt.JwtMlDsaPrivateKey;
import com.google.crypto.tink.jwt.JwtMlDsaPublicKey;
import com.google.crypto.tink.proto.JwtMlDsaAlgorithm;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaPrivateKey;
import com.google.crypto.tink.signature.internal.testing.MlDsaTestUtil;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Optional;
import javax.annotation.Nullable;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
@AccessesPartialKey
public final class JwtMlDsaProtoSerializationTest {
  private static final String PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey";
  private static final String PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey";

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  private static final MlDsaPrivateKey MLDSA_44_KEY =
      (MlDsaPrivateKey)
          MlDsaTestUtil.getMlDsaValidSignatureTestVector(
                  MlDsaParameters.create(
                      MlDsaParameters.MlDsaInstance.ML_DSA_44,
                      MlDsaParameters.Variant.NO_PREFIX))
              .getPrivateKey();
  private static final MlDsaPrivateKey MLDSA_65_KEY =
      (MlDsaPrivateKey)
          MlDsaTestUtil.getMlDsaValidSignatureTestVector(
                  MlDsaParameters.create(
                      MlDsaParameters.MlDsaInstance.ML_DSA_65,
                      MlDsaParameters.Variant.NO_PREFIX))
              .getPrivateKey();
  private static final MlDsaPrivateKey MLDSA_87_KEY =
      (MlDsaPrivateKey)
          MlDsaTestUtil.getMlDsaValidSignatureTestVector(
                  MlDsaParameters.create(
                      MlDsaParameters.MlDsaInstance.ML_DSA_87,
                      MlDsaParameters.Variant.NO_PREFIX))
              .getPrivateKey();

  @BeforeClass
  public static void setUp() throws Exception {
    JwtMlDsaProtoSerialization.register(registry);
  }

  private static class TestVector {
    final JwtMlDsaParameters.KidStrategy kidStrategy;
    final JwtMlDsaParameters.Algorithm algorithm;
    final Optional<String> kid;
    final Integer idRequirement;

    TestVector(
        JwtMlDsaParameters.KidStrategy kidStrategy,
        JwtMlDsaParameters.Algorithm algorithm,
        Optional<String> kid,
        @Nullable Integer idRequirement) {
      this.kidStrategy = kidStrategy;
      this.algorithm = algorithm;
      this.kid = kid;
      this.idRequirement = idRequirement;
    }
  }

  @DataPoints("ml_dsa_test_vectors")
  public static final TestVector[] testVectors = {
    new TestVector(
        JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
        JwtMlDsaParameters.Algorithm.ML_DSA_44,
        /* kid= */ Optional.of("GsapRA"),
        /* idRequirement= */ 0x1ac6a944),
    new TestVector(
        JwtMlDsaParameters.KidStrategy.IGNORED,
        JwtMlDsaParameters.Algorithm.ML_DSA_65,
        /* kid= */ Optional.empty(),
        /* idRequirement= */ null),
    new TestVector(
        JwtMlDsaParameters.KidStrategy.CUSTOM,
        JwtMlDsaParameters.Algorithm.ML_DSA_87,
        /* kid= */ Optional.of("custom_kid"),
        /* idRequirement= */ null)
  };



  private static JwtMlDsaAlgorithm getProtoAlgorithm(JwtMlDsaParameters.Algorithm algorithm) {
    if (algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_44)) {
      return JwtMlDsaAlgorithm.ML_DSA44;
    }
    if (algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_65)) {
      return JwtMlDsaAlgorithm.ML_DSA65;
    }
    if (algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_87)) {
      return JwtMlDsaAlgorithm.ML_DSA87;
    }
    throw new IllegalArgumentException("Unknown algorithm: " + algorithm);
  }

  private static Bytes getPublicKeyBytes(TestVector testVector) {
    if (testVector.algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_44)) {
      return MLDSA_44_KEY.getPublicKey().getSerializedPublicKey();
    }
    if (testVector.algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_65)) {
      return MLDSA_65_KEY.getPublicKey().getSerializedPublicKey();
    }
    if (testVector.algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_87)) {
      return MLDSA_87_KEY.getPublicKey().getSerializedPublicKey();
    }
    throw new IllegalArgumentException("Unknown algorithm: " + testVector.algorithm);
  }

  private static SecretBytes getPrivateSeed(TestVector testVector) {
    if (testVector.algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_44)) {
      return MLDSA_44_KEY.getPrivateSeed();
    }
    if (testVector.algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_65)) {
      return MLDSA_65_KEY.getPrivateSeed();
    }
    if (testVector.algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_87)) {
      return MLDSA_87_KEY.getPrivateSeed();
    }
    throw new IllegalArgumentException("Unknown algorithm: " + testVector.algorithm);
  }

  private static JwtMlDsaParameters createParameters(TestVector testVector) throws Exception {
    return JwtMlDsaParameters.create(testVector.kidStrategy, testVector.algorithm);
  }

  private static JwtMlDsaPublicKey createPublicKey(TestVector testVector) throws Exception {
    JwtMlDsaParameters parameters = createParameters(testVector);
    Bytes publicKeyBytes = getPublicKeyBytes(testVector);
    JwtMlDsaPublicKey.Builder builder =
        JwtMlDsaPublicKey.builder().setParameters(parameters).setPublicKeyBytes(publicKeyBytes);
    if (testVector.idRequirement != null) {
      builder.setIdRequirement(testVector.idRequirement);
    }
    if (testVector.kidStrategy == JwtMlDsaParameters.KidStrategy.CUSTOM) {
      builder.setCustomKid(testVector.kid.get());
    }
    return builder.build();
  }

  private static JwtMlDsaPrivateKey createPrivateKey(TestVector testVector) throws Exception {
    JwtMlDsaPublicKey publicKey = createPublicKey(testVector);
    SecretBytes privateSeed = getPrivateSeed(testVector);
    return JwtMlDsaPrivateKey.create(publicKey, privateSeed);
  }

  private static ProtoParametersSerialization createProtoParametersSerialization(
      TestVector testVector) throws Exception {
    OutputPrefixType outputPrefixType =
        testVector.kidStrategy == JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID
            ? OutputPrefixType.TINK
            : OutputPrefixType.RAW;
    com.google.crypto.tink.proto.JwtMlDsaKeyFormat format =
        com.google.crypto.tink.proto.JwtMlDsaKeyFormat.newBuilder()
            .setVersion(0)
            .setAlgorithm(getProtoAlgorithm(testVector.algorithm))
            .build();
    return ProtoParametersSerialization.create(
        PRIVATE_TYPE_URL, outputPrefixType, format.toByteString());
  }

  private static ProtoKeySerialization createProtoPublicKeySerialization(TestVector testVector)
      throws Exception {
    OutputPrefixType outputPrefixType =
        testVector.kidStrategy == JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID
            ? OutputPrefixType.TINK
            : OutputPrefixType.RAW;

    com.google.crypto.tink.proto.JwtMlDsaPublicKey.Builder builder =
        com.google.crypto.tink.proto.JwtMlDsaPublicKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(getProtoAlgorithm(testVector.algorithm))
            .setKeyValue(ByteString.copyFrom(getPublicKeyBytes(testVector).toByteArray()));

    if (testVector.kidStrategy == JwtMlDsaParameters.KidStrategy.CUSTOM) {
      builder.setCustomKid(
          com.google.crypto.tink.proto.JwtMlDsaPublicKey.CustomKid.newBuilder()
              .setValue(testVector.kid.get())
              .build());
    }

    return ProtoKeySerialization.create(
        PUBLIC_TYPE_URL,
        builder.build().toByteString(),
        KeyMaterialType.ASYMMETRIC_PUBLIC,
        outputPrefixType,
        testVector.idRequirement);
  }

  private static ProtoKeySerialization createProtoPrivateKeySerialization(TestVector testVector)
      throws Exception {
    OutputPrefixType outputPrefixType =
        testVector.kidStrategy == JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID
            ? OutputPrefixType.TINK
            : OutputPrefixType.RAW;

    com.google.crypto.tink.proto.JwtMlDsaPublicKey.Builder publicKeyProtoBuilder =
        com.google.crypto.tink.proto.JwtMlDsaPublicKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(getProtoAlgorithm(testVector.algorithm))
            .setKeyValue(ByteString.copyFrom(getPublicKeyBytes(testVector).toByteArray()));

    if (testVector.kidStrategy == JwtMlDsaParameters.KidStrategy.CUSTOM) {
      publicKeyProtoBuilder.setCustomKid(
          com.google.crypto.tink.proto.JwtMlDsaPublicKey.CustomKid.newBuilder()
              .setValue(testVector.kid.get())
              .build());
    }

    com.google.crypto.tink.proto.JwtMlDsaPrivateKey privateKeyProto =
        com.google.crypto.tink.proto.JwtMlDsaPrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(publicKeyProtoBuilder.build())
            .setKeyValue(
                ByteString.copyFrom(
                    getPrivateSeed(testVector).toByteArray(InsecureSecretKeyAccess.get())))
            .build();

    return ProtoKeySerialization.create(
        PRIVATE_TYPE_URL,
        privateKeyProto.toByteString(),
        KeyMaterialType.ASYMMETRIC_PRIVATE,
        outputPrefixType,
        testVector.idRequirement);
  }

  @Theory
  public void serializeParseParameters_succeeds(
      @FromDataPoints("ml_dsa_test_vectors") TestVector testVector) throws Exception {
    if (testVector.kidStrategy == JwtMlDsaParameters.KidStrategy.CUSTOM) {
      // Custom KidStrategy parameters cannot be serialized to proto parameters.
      return;
    }
    JwtMlDsaParameters parameters = createParameters(testVector);
    ProtoParametersSerialization expectedSerialization =
        createProtoParametersSerialization(testVector);

    ProtoParametersSerialization serialized = registry.serializeParameters(parameters);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtMlDsaKeyFormat.parser(), serialized, expectedSerialization);

    Parameters parsed = registry.parseParameters(expectedSerialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Theory
  public void serializeParsePublicKey_succeeds(
      @FromDataPoints("ml_dsa_test_vectors") TestVector testVector) throws Exception {
    JwtMlDsaPublicKey publicKey = createPublicKey(testVector);
    ProtoKeySerialization expectedSerialization = createProtoPublicKeySerialization(testVector);

    ProtoKeySerialization serialized = registry.serializeKey(publicKey, /* access= */ null);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtMlDsaPublicKey.parser(), serialized, expectedSerialization);

    Key parsed = registry.parseKey(expectedSerialization, /* access= */ null);
    assertThat(parsed.equalsKey(publicKey)).isTrue();
  }

  @Theory
  public void serializeParsePrivateKey_succeeds(
      @FromDataPoints("ml_dsa_test_vectors") TestVector testVector) throws Exception {
    JwtMlDsaPrivateKey privateKey = createPrivateKey(testVector);
    ProtoKeySerialization expectedSerialization = createProtoPrivateKeySerialization(testVector);

    ProtoKeySerialization serialized =
        registry.serializeKey(privateKey, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtMlDsaPrivateKey.parser(),
        serialized,
        expectedSerialization);

    Key parsed = registry.parseKey(expectedSerialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(privateKey)).isTrue();
  }

  @Test
  public void serializeParameters_customKidStrategy_throws() throws Exception {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.CUSTOM, JwtMlDsaParameters.Algorithm.ML_DSA_44);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> registry.serializeParameters(parameters));
    assertThat(e)
        .hasMessageThat()
        .contains("Unable to serialize Parameters object with KidStrategy CUSTOM");
  }

  @Test
  public void parseParameters_wrongTypeUrl_throws() throws Exception {
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "wrong.type.url",
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.JwtMlDsaKeyFormat.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtMlDsaAlgorithm.ML_DSA44)
                .build()
                .toByteString());

    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
    assertThat(e).hasMessageThat().contains("No Parameters Parser for requested key type");
  }

  @Test
  public void parseParameters_invalidProto_throws() throws Exception {
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL, OutputPrefixType.RAW, ByteString.copyFrom(new byte[] {(byte) 0x80}));

    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
    assertThat(e).hasMessageThat().contains("Parsing JwtMlDsaKeyFormat failed: ");
  }

  @Test
  public void parseParameters_invalidVersion_throws() throws Exception {
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.JwtMlDsaKeyFormat.newBuilder()
                .setVersion(1) // Invalid version.
                .setAlgorithm(JwtMlDsaAlgorithm.ML_DSA44)
                .build()
                .toByteString());

    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
    assertThat(e).hasMessageThat().contains("Parsing JwtMlDsaParameters failed: unknown version");
  }

  @Test
  public void parseParameters_invalidOutputPrefixType_throws() throws Exception {
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.CRUNCHY,
            com.google.crypto.tink.proto.JwtMlDsaKeyFormat.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtMlDsaAlgorithm.ML_DSA44)
                .build()
                .toByteString());

    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
    assertThat(e).hasMessageThat().contains("Invalid OutputPrefixType for JwtMlDsaKeyFormat");
  }

  @Test
  public void parseParameters_unknownAlgorithm_throws() throws Exception {
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.JwtMlDsaKeyFormat.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtMlDsaAlgorithm.ML_DSA_UNKNOWN)
                .build()
                .toByteString());

    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
    assertThat(e).hasMessageThat().contains("Unable to parse algorithm");
  }

  @Test
  public void parsePublicKey_wrongTypeUrl_throws() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "wrong.type.url",
            com.google.crypto.tink.proto.JwtMlDsaPublicKey.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtMlDsaAlgorithm.ML_DSA44)
                .setKeyValue(ByteString.copyFrom(new byte[1312]))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> registry.parseKey(serialization, /* access= */ null));
    assertThat(e).hasMessageThat().contains("No Key Parser for requested key type");
  }

  @Test
  public void parsePublicKey_invalidProto_throws() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            ByteString.copyFrom(new byte[] {(byte) 0x80}),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> registry.parseKey(serialization, /* access= */ null));
    assertThat(e).hasMessageThat().contains("Parsing JwtMlDsaPublicKey failed: ");
  }

  @Test
  public void parsePublicKey_invalidVersion_throws() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            com.google.crypto.tink.proto.JwtMlDsaPublicKey.newBuilder()
                .setVersion(1)
                .setAlgorithm(JwtMlDsaAlgorithm.ML_DSA44)
                .setKeyValue(ByteString.copyFrom(new byte[1312]))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> registry.parseKey(serialization, /* access= */ null));
    assertThat(e).hasMessageThat().contains("Only version 0 keys are accepted");
  }

  @Test
  public void parsePublicKey_tinkPrefixWithCustomKid_throws() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            com.google.crypto.tink.proto.JwtMlDsaPublicKey.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtMlDsaAlgorithm.ML_DSA44)
                .setKeyValue(
                    ByteString.copyFrom(
                        MLDSA_44_KEY.getPublicKey().getSerializedPublicKey().toByteArray()))
                .setCustomKid(
                    com.google.crypto.tink.proto.JwtMlDsaPublicKey.CustomKid.newBuilder()
                        .setValue("custom")
                        .build())
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 1234);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> registry.parseKey(serialization, /* access= */ null));
    assertThat(e)
        .hasMessageThat()
        .contains("Keys serialized with OutputPrefixType TINK should not have a custom kid");
  }

  @Test
  public void parsePublicKey_invalidOutputPrefixType_throws() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            com.google.crypto.tink.proto.JwtMlDsaPublicKey.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtMlDsaAlgorithm.ML_DSA44)
                .setKeyValue(
                    ByteString.copyFrom(
                        MLDSA_44_KEY.getPublicKey().getSerializedPublicKey().toByteArray()))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.CRUNCHY,
            /* idRequirement= */ 1234);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> registry.parseKey(serialization, /* access= */ null));
    assertThat(e).hasMessageThat().contains("Unsupported output prefix");
  }

  @Test
  public void serializePrivateKey_noSecretKeyAccess_throws() throws Exception {
    JwtMlDsaPrivateKey privateKey = createPrivateKey(testVectors[0]);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> registry.serializeKey(privateKey, /* access= */ null));
    assertThat(e).hasMessageThat().contains("SecretKeyAccess is required");
  }

  @Test
  public void parsePrivateKey_wrongTypeUrl_throws() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "wrong.type.url",
            com.google.crypto.tink.proto.JwtMlDsaPrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(
                    com.google.crypto.tink.proto.JwtMlDsaPublicKey.newBuilder()
                        .setVersion(0)
                        .setAlgorithm(JwtMlDsaAlgorithm.ML_DSA44)
                        .setKeyValue(
                            ByteString.copyFrom(
                                MLDSA_44_KEY
                                    .getPublicKey()
                                    .getSerializedPublicKey()
                                    .toByteArray())))
                .setKeyValue(
                    ByteString.copyFrom(
                        MLDSA_44_KEY
                            .getPrivateSeed()
                            .toByteArray(InsecureSecretKeyAccess.get())))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
    assertThat(e).hasMessageThat().contains("No Key Parser for requested key type");
  }

  @Test
  public void parsePrivateKey_invalidProto_throws() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            ByteString.copyFrom(new byte[] {(byte) 0x80}),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
    assertThat(e).hasMessageThat().contains("Parsing JwtMlDsaPrivateKey failed: ");
  }

  @Test
  public void parsePrivateKey_invalidVersion_throws() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            com.google.crypto.tink.proto.JwtMlDsaPrivateKey.newBuilder()
                .setVersion(1)
                .setPublicKey(
                    com.google.crypto.tink.proto.JwtMlDsaPublicKey.newBuilder()
                        .setVersion(0)
                        .setAlgorithm(JwtMlDsaAlgorithm.ML_DSA44)
                        .setKeyValue(ByteString.copyFrom(new byte[1312])))
                .setKeyValue(ByteString.copyFrom(new byte[32]))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
    assertThat(e).hasMessageThat().contains("Only version 0 keys are accepted");
  }

  @Test
  public void parsePrivateKey_noSecretKeyAccess_throws() throws Exception {
    ProtoKeySerialization serialization = createProtoPrivateKeySerialization(testVectors[0]);

    NullPointerException e =
        assertThrows(
            NullPointerException.class, () -> registry.parseKey(serialization, /* access= */ null));
    assertThat(e).hasMessageThat().contains("SecretKeyAccess required");
  }
}
