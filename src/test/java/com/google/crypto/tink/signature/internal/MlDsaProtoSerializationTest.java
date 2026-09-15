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

package com.google.crypto.tink.signature.internal;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.testing.Asserts.assertEqualWhenValueParsed;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType;
import com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType;
import com.google.crypto.tink.ProtoParametersSerialization;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.proto.MlDsaKeyFormat;
import com.google.crypto.tink.proto.MlDsaParams;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.MlDsaParameters.Variant;
import com.google.crypto.tink.signature.MlDsaPrivateKey;
import com.google.crypto.tink.signature.MlDsaPublicKey;
import com.google.crypto.tink.signature.internal.testing.MlDsaTestUtil;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@AccessesPartialKey
@RunWith(Theories.class)
public class MlDsaProtoSerializationTest {

  private static final String PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey";
  private static final String PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.MlDsaPublicKey";

  private static final MlDsaPrivateKey MLDSA_44_KEY =
      (MlDsaPrivateKey)
          MlDsaTestUtil.getMlDsaValidSignatureTestVector(
                  MlDsaParameters.create(MlDsaInstance.ML_DSA_44, Variant.NO_PREFIX))
              .getPrivateKey();
  private static final Bytes PUBLIC_KEY_ML_DSA_44_BYTES =
      MLDSA_44_KEY.getPublicKey().getSerializedPublicKey();
  private static final ByteString PUBLIC_KEY_ML_DSA_44_BYTE_STRING =
      ByteString.copyFrom(MLDSA_44_KEY.getPublicKey().getSerializedPublicKey().toByteArray());

  private static final SecretBytes PRIVATE_KEY_ML_DSA_44_SEED_SECRET_BYTES =
      MLDSA_44_KEY.getPrivateSeed();
  private static final ByteString PRIVATE_KEY_ML_DSA_44_SEED_BYTE_STRING =
      ByteString.copyFrom(
          MLDSA_44_KEY.getPrivateSeed().toByteArray(InsecureSecretKeyAccess.get()));

  private static final MlDsaPrivateKey MLDSA_65_KEY =
      (MlDsaPrivateKey)
          MlDsaTestUtil.getMlDsaValidSignatureTestVector(
                  MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.NO_PREFIX))
              .getPrivateKey();
  private static final Bytes PUBLIC_KEY_ML_DSA_65_BYTES =
      MLDSA_65_KEY.getPublicKey().getSerializedPublicKey();
  private static final ByteString PUBLIC_KEY_ML_DSA_65_BYTE_STRING =
      ByteString.copyFrom(
          MLDSA_65_KEY.getPublicKey().getSerializedPublicKey().toByteArray());

  private static final SecretBytes PRIVATE_KEY_ML_DSA_65_SEED_SECRET_BYTES =
      MLDSA_65_KEY.getPrivateSeed();
  private static final ByteString PRIVATE_KEY_ML_DSA_65_SEED_BYTE_STRING =
      ByteString.copyFrom(
          MLDSA_65_KEY.getPrivateSeed().toByteArray(InsecureSecretKeyAccess.get()));

  private static final MlDsaPrivateKey MLDSA_87_KEY =
      (MlDsaPrivateKey)
          MlDsaTestUtil.getMlDsaValidSignatureTestVector(
                  MlDsaParameters.create(MlDsaInstance.ML_DSA_87, Variant.NO_PREFIX))
              .getPrivateKey();
  private static final Bytes PUBLIC_KEY_ML_DSA_87_BYTES =
      MLDSA_87_KEY.getPublicKey().getSerializedPublicKey();
  private static final ByteString PUBLIC_KEY_ML_DSA_87_BYTE_STRING =
      ByteString.copyFrom(
          MLDSA_87_KEY.getPublicKey().getSerializedPublicKey().toByteArray());

  private static final SecretBytes PRIVATE_KEY_ML_DSA_87_SEED_SECRET_BYTES =
      MLDSA_87_KEY.getPrivateSeed();
  private static final ByteString PRIVATE_KEY_ML_DSA_87_SEED_BYTE_STRING =
      ByteString.copyFrom(
          MLDSA_87_KEY.getPrivateSeed().toByteArray(InsecureSecretKeyAccess.get()));

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  @BeforeClass
  public static void setUp() throws Exception {
    MlDsaProtoSerialization.register(registry);
  }

  // Parameters correctness tests.
  private static final class ParametersSerializationTestPair {
    MlDsaParameters parameters;
    ProtoParametersSerialization serialization;

    ParametersSerializationTestPair(
        MlDsaParameters parameters, ProtoParametersSerialization serialization) {
      this.parameters = parameters;
      this.serialization = serialization;
    }
  }

  private static List<ParametersSerializationTestPair> createParametersSerializationTestPairs() {
    try {
      return Arrays.asList(
          new ParametersSerializationTestPair(
              MlDsaParameters.create(MlDsaInstance.ML_DSA_44, Variant.NO_PREFIX),
              ProtoParametersSerialization.create(
                  PRIVATE_TYPE_URL,
                  OutputPrefixType.RAW,
                  MlDsaKeyFormat.newBuilder()
                      .setParams(
                          MlDsaParams.newBuilder()
                              .setMlDsaInstance(
                                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_44))
                      .build()
                      .toByteString())),
          new ParametersSerializationTestPair(
              MlDsaParameters.create(MlDsaInstance.ML_DSA_44, Variant.TINK),
              ProtoParametersSerialization.create(
                  PRIVATE_TYPE_URL,
                  OutputPrefixType.TINK,
                  MlDsaKeyFormat.newBuilder()
                      .setParams(
                          MlDsaParams.newBuilder()
                              .setMlDsaInstance(
                                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_44))
                      .build()
                      .toByteString())),
          new ParametersSerializationTestPair(
              MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.NO_PREFIX),
              ProtoParametersSerialization.create(
                  PRIVATE_TYPE_URL,
                  OutputPrefixType.RAW,
                  MlDsaKeyFormat.newBuilder()
                      .setParams(
                          MlDsaParams.newBuilder()
                              .setMlDsaInstance(
                                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                      .build()
                      .toByteString())),
          new ParametersSerializationTestPair(
              MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.TINK),
              ProtoParametersSerialization.create(
                  PRIVATE_TYPE_URL,
                  OutputPrefixType.TINK,
                  MlDsaKeyFormat.newBuilder()
                      .setParams(
                          MlDsaParams.newBuilder()
                              .setMlDsaInstance(
                                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                      .build()
                      .toByteString())),
          new ParametersSerializationTestPair(
              MlDsaParameters.create(MlDsaInstance.ML_DSA_87, Variant.NO_PREFIX),
              ProtoParametersSerialization.create(
                  PRIVATE_TYPE_URL,
                  OutputPrefixType.RAW,
                  MlDsaKeyFormat.newBuilder()
                      .setParams(
                          MlDsaParams.newBuilder()
                              .setMlDsaInstance(
                                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                      .build()
                      .toByteString())),
          new ParametersSerializationTestPair(
              MlDsaParameters.create(MlDsaInstance.ML_DSA_87, Variant.TINK),
              ProtoParametersSerialization.create(
                  PRIVATE_TYPE_URL,
                  OutputPrefixType.TINK,
                  MlDsaKeyFormat.newBuilder()
                      .setParams(
                          MlDsaParams.newBuilder()
                              .setMlDsaInstance(
                                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                      .build()
                      .toByteString())));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  @DataPoints("parametersSerializationTestPairList")
  public static final List<ParametersSerializationTestPair> parametersSerializationTestPairList =
      createParametersSerializationTestPairs();

  @Theory
  public void serializeParseParameters_equal(
      @FromDataPoints("parametersSerializationTestPairList") ParametersSerializationTestPair pair)
      throws Exception {
    ProtoParametersSerialization serialized = registry.serializeParameters(pair.parameters);
    Parameters parsed = registry.parseParameters(pair.serialization);

    assertEqualWhenValueParsed(MlDsaKeyFormat.parser(), serialized, pair.serialization);
    assertThat(parsed).isEqualTo(pair.parameters);
  }

  // Public key correctness tests.
  private static final class PublicKeySerializationTestPair {
    MlDsaPublicKey key;
    ProtoKeySerialization serialization;

    PublicKeySerializationTestPair(MlDsaPublicKey key, ProtoKeySerialization serialization) {
      this.key = key;
      this.serialization = serialization;
    }
  }

  @DataPoints("publicKeySerializationTestPairList")
  public static final List<PublicKeySerializationTestPair> publicKeySerializationTestPairList =
      createPublicKeySerializationTestPairs();

  private static List<PublicKeySerializationTestPair> createPublicKeySerializationTestPairs() {
    try {
      return Arrays.asList(
          new PublicKeySerializationTestPair(
              MlDsaPublicKey.builder()
                  .setParameters(MlDsaParameters.create(MlDsaInstance.ML_DSA_44, Variant.NO_PREFIX))
                  .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_44_BYTES)
                  .build(),
              ProtoKeySerialization.create(
                  PUBLIC_TYPE_URL,
                  com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                      .setParams(
                          MlDsaParams.newBuilder()
                              .setMlDsaInstance(
                                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_44))
                      .setKeyValue(PUBLIC_KEY_ML_DSA_44_BYTE_STRING)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PUBLIC,
                  OutputPrefixType.RAW,
                  /* idRequirement= */ null)),
          new PublicKeySerializationTestPair(
              MlDsaPublicKey.builder()
                  .setParameters(MlDsaParameters.create(MlDsaInstance.ML_DSA_44, Variant.TINK))
                  .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_44_BYTES)
                  .setIdRequirement(0x12345678)
                  .build(),
              ProtoKeySerialization.create(
                  PUBLIC_TYPE_URL,
                  com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                      .setParams(
                          MlDsaParams.newBuilder()
                              .setMlDsaInstance(
                                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_44))
                      .setKeyValue(PUBLIC_KEY_ML_DSA_44_BYTE_STRING)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PUBLIC,
                  OutputPrefixType.TINK,
                  /* idRequirement= */ 0x12345678)),
          new PublicKeySerializationTestPair(
              MlDsaPublicKey.builder()
                  .setParameters(MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.NO_PREFIX))
                  .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_65_BYTES)
                  .build(),
              ProtoKeySerialization.create(
                  PUBLIC_TYPE_URL,
                  com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                      .setParams(
                          MlDsaParams.newBuilder()
                              .setMlDsaInstance(
                                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                      .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PUBLIC,
                  OutputPrefixType.RAW,
                  /* idRequirement= */ null)),
          new PublicKeySerializationTestPair(
              MlDsaPublicKey.builder()
                  .setParameters(MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.TINK))
                  .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_65_BYTES)
                  .setIdRequirement(0x12345678)
                  .build(),
              ProtoKeySerialization.create(
                  PUBLIC_TYPE_URL,
                  com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                      .setParams(
                          MlDsaParams.newBuilder()
                              .setMlDsaInstance(
                                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                      .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PUBLIC,
                  OutputPrefixType.TINK,
                  /* idRequirement= */ 0x12345678)),
          new PublicKeySerializationTestPair(
              MlDsaPublicKey.builder()
                  .setParameters(MlDsaParameters.create(MlDsaInstance.ML_DSA_87, Variant.NO_PREFIX))
                  .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_87_BYTES)
                  .build(),
              ProtoKeySerialization.create(
                  PUBLIC_TYPE_URL,
                  com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                      .setParams(
                          MlDsaParams.newBuilder()
                              .setMlDsaInstance(
                                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                      .setKeyValue(PUBLIC_KEY_ML_DSA_87_BYTE_STRING)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PUBLIC,
                  OutputPrefixType.RAW,
                  /* idRequirement= */ null)),
          new PublicKeySerializationTestPair(
              MlDsaPublicKey.builder()
                  .setParameters(MlDsaParameters.create(MlDsaInstance.ML_DSA_87, Variant.TINK))
                  .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_87_BYTES)
                  .setIdRequirement(0x12345678)
                  .build(),
              ProtoKeySerialization.create(
                  PUBLIC_TYPE_URL,
                  com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                      .setParams(
                          MlDsaParams.newBuilder()
                              .setMlDsaInstance(
                                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                      .setKeyValue(PUBLIC_KEY_ML_DSA_87_BYTE_STRING)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PUBLIC,
                  OutputPrefixType.TINK,
                  /* idRequirement= */ 0x12345678)));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  @Theory
  public void serializeParsePublicKey_equal(
      @FromDataPoints("publicKeySerializationTestPairList") PublicKeySerializationTestPair pair)
      throws Exception {
    ProtoKeySerialization serialized = registry.serializeKey(pair.key, null);
    Key parsed = registry.parseKey(pair.serialization, null);

    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.MlDsaPublicKey.parser(), serialized, pair.serialization);
    assertTrue(parsed.equalsKey(pair.key));
  }

  // Private key correctness tests.
  private static final class PrivateKeySerializationTestPair {
    MlDsaPrivateKey key;
    ProtoKeySerialization serialization;

    PrivateKeySerializationTestPair(MlDsaPrivateKey key, ProtoKeySerialization serialization) {
      this.key = key;
      this.serialization = serialization;
    }
  }

  @DataPoints("privateKeySerializationTestPairList")
  public static final List<PrivateKeySerializationTestPair> privateKeySerializationTestPairList =
      createPrivateKeySerializationTestPairs();

  private static List<PrivateKeySerializationTestPair> createPrivateKeySerializationTestPairs() {
    try {
      MlDsaPublicKey noPrefixPublicKey44 =
          MlDsaPublicKey.builder()
              .setParameters(MlDsaParameters.create(MlDsaInstance.ML_DSA_44, Variant.NO_PREFIX))
              .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_44_BYTES)
              .build();
      MlDsaPublicKey tinkPublicKey44 =
          MlDsaPublicKey.builder()
              .setParameters(MlDsaParameters.create(MlDsaInstance.ML_DSA_44, Variant.TINK))
              .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_44_BYTES)
              .setIdRequirement(0x12345678)
              .build();
      MlDsaPublicKey noPrefixPublicKey65 =
          MlDsaPublicKey.builder()
              .setParameters(MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.NO_PREFIX))
              .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_65_BYTES)
              .build();
      MlDsaPublicKey tinkPublicKey65 =
          MlDsaPublicKey.builder()
              .setParameters(MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.TINK))
              .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_65_BYTES)
              .setIdRequirement(0x12345678)
              .build();
      MlDsaPublicKey noPrefixPublicKey87 =
          MlDsaPublicKey.builder()
              .setParameters(MlDsaParameters.create(MlDsaInstance.ML_DSA_87, Variant.NO_PREFIX))
              .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_87_BYTES)
              .build();
      MlDsaPublicKey tinkPublicKey87 =
          MlDsaPublicKey.builder()
              .setParameters(MlDsaParameters.create(MlDsaInstance.ML_DSA_87, Variant.TINK))
              .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_87_BYTES)
              .setIdRequirement(0x12345678)
              .build();
      return Arrays.asList(
          new PrivateKeySerializationTestPair(
              MlDsaPrivateKey.createWithoutVerification(
                  noPrefixPublicKey44, PRIVATE_KEY_ML_DSA_44_SEED_SECRET_BYTES),
              ProtoKeySerialization.create(
                  PRIVATE_TYPE_URL,
                  com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                      .setPublicKey(
                          com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                              .setParams(
                                  MlDsaParams.newBuilder()
                                      .setMlDsaInstance(
                                          com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_44))
                              .setKeyValue(PUBLIC_KEY_ML_DSA_44_BYTE_STRING))
                      .setKeyValue(PRIVATE_KEY_ML_DSA_44_SEED_BYTE_STRING)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PRIVATE,
                  OutputPrefixType.RAW,
                  /* idRequirement= */ null)),
          new PrivateKeySerializationTestPair(
              MlDsaPrivateKey.createWithoutVerification(
                  tinkPublicKey44, PRIVATE_KEY_ML_DSA_44_SEED_SECRET_BYTES),
              ProtoKeySerialization.create(
                  PRIVATE_TYPE_URL,
                  com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                      .setPublicKey(
                          com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                              .setParams(
                                  MlDsaParams.newBuilder()
                                      .setMlDsaInstance(
                                          com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_44))
                              .setKeyValue(PUBLIC_KEY_ML_DSA_44_BYTE_STRING))
                      .setKeyValue(PRIVATE_KEY_ML_DSA_44_SEED_BYTE_STRING)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PRIVATE,
                  OutputPrefixType.TINK,
                  /* idRequirement= */ 0x12345678)),
          new PrivateKeySerializationTestPair(
              MlDsaPrivateKey.createWithoutVerification(
                  noPrefixPublicKey65, PRIVATE_KEY_ML_DSA_65_SEED_SECRET_BYTES),
              ProtoKeySerialization.create(
                  PRIVATE_TYPE_URL,
                  com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                      .setPublicKey(
                          com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                              .setParams(
                                  MlDsaParams.newBuilder()
                                      .setMlDsaInstance(
                                          com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                              .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING))
                      .setKeyValue(PRIVATE_KEY_ML_DSA_65_SEED_BYTE_STRING)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PRIVATE,
                  OutputPrefixType.RAW,
                  /* idRequirement= */ null)),
          new PrivateKeySerializationTestPair(
              MlDsaPrivateKey.createWithoutVerification(
                  tinkPublicKey65, PRIVATE_KEY_ML_DSA_65_SEED_SECRET_BYTES),
              ProtoKeySerialization.create(
                  PRIVATE_TYPE_URL,
                  com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                      .setPublicKey(
                          com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                              .setParams(
                                  MlDsaParams.newBuilder()
                                      .setMlDsaInstance(
                                          com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                              .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING))
                      .setKeyValue(PRIVATE_KEY_ML_DSA_65_SEED_BYTE_STRING)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PRIVATE,
                  OutputPrefixType.TINK,
                  /* idRequirement= */ 0x12345678)),
          new PrivateKeySerializationTestPair(
              MlDsaPrivateKey.createWithoutVerification(
                  noPrefixPublicKey87, PRIVATE_KEY_ML_DSA_87_SEED_SECRET_BYTES),
              ProtoKeySerialization.create(
                  PRIVATE_TYPE_URL,
                  com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                      .setPublicKey(
                          com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                              .setParams(
                                  MlDsaParams.newBuilder()
                                      .setMlDsaInstance(
                                          com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                              .setKeyValue(PUBLIC_KEY_ML_DSA_87_BYTE_STRING))
                      .setKeyValue(PRIVATE_KEY_ML_DSA_87_SEED_BYTE_STRING)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PRIVATE,
                  OutputPrefixType.RAW,
                  /* idRequirement= */ null)),
          new PrivateKeySerializationTestPair(
              MlDsaPrivateKey.createWithoutVerification(
                  tinkPublicKey87, PRIVATE_KEY_ML_DSA_87_SEED_SECRET_BYTES),
              ProtoKeySerialization.create(
                  PRIVATE_TYPE_URL,
                  com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                      .setPublicKey(
                          com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                              .setParams(
                                  MlDsaParams.newBuilder()
                                      .setMlDsaInstance(
                                          com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                              .setKeyValue(PUBLIC_KEY_ML_DSA_87_BYTE_STRING))
                      .setKeyValue(PRIVATE_KEY_ML_DSA_87_SEED_BYTE_STRING)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PRIVATE,
                  OutputPrefixType.TINK,
                  /* idRequirement= */ 0x12345678)));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  @Theory
  public void serializeParsePrivateKey_equal(
      @FromDataPoints("privateKeySerializationTestPairList") PrivateKeySerializationTestPair pair)
      throws Exception {
    ProtoKeySerialization serialized =
        registry.serializeKey(pair.key, InsecureSecretKeyAccess.get());
    Key parsed = registry.parseKey(pair.serialization, InsecureSecretKeyAccess.get());

    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.MlDsaPrivateKey.parser(), serialized, pair.serialization);
    assertTrue(parsed.equalsKey(pair.key));
  }

  // Test failure modes
  @Test
  public void serializePrivateKeyWithoutAccess_throws() throws Exception {
    MlDsaPrivateKey privateKey = privateKeySerializationTestPairList.get(0).key;
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.serializeKey(privateKey, /* access= */ null));
  }

  @Test
  public void parsePrivateKeyWithoutAccess_throws() throws Exception {
    ProtoKeySerialization serialization = privateKeySerializationTestPairList.get(0).serialization;
    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }

  private static List<ProtoParametersSerialization> createInvalidParameters() {
    try {
      return Arrays.asList(
          // Unknown output prefix
          ProtoParametersSerialization.create(
              PRIVATE_TYPE_URL,
              OutputPrefixType.UNKNOWN_PREFIX,
              MlDsaKeyFormat.newBuilder()
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                  .build()
                  .toByteString()),
          // Invalid version
          ProtoParametersSerialization.create(
              PRIVATE_TYPE_URL,
              OutputPrefixType.RAW,
              MlDsaKeyFormat.newBuilder()
                  .setVersion(1)
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                  .build()
                  .toByteString()),
          // Unknown instance
          ProtoParametersSerialization.create(
              PRIVATE_TYPE_URL,
              OutputPrefixType.RAW,
              MlDsaKeyFormat.newBuilder()
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(
                              com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_UNKNOWN_INSTANCE))
                  .build()
                  .toByteString()),
          // Invalid proto serialization
          ProtoParametersSerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.RAW,
              ByteString.copyFrom(new byte[] {(byte) 0x80})),
          // Invalid type url (which will cause the wrong parser being invoked, and that parser will
          // not accept this proto)
          ProtoParametersSerialization.create(
              PUBLIC_TYPE_URL,
              OutputPrefixType.RAW,
              MlDsaKeyFormat.newBuilder()
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                  .build()
                  .toByteString()),
          // Unknown output prefix for ML_DSA_87
          ProtoParametersSerialization.create(
              PRIVATE_TYPE_URL,
              OutputPrefixType.UNKNOWN_PREFIX,
              MlDsaKeyFormat.newBuilder()
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                  .build()
                  .toByteString()),
          // Invalid version for ML_DSA_87
          ProtoParametersSerialization.create(
              PRIVATE_TYPE_URL,
              OutputPrefixType.RAW,
              MlDsaKeyFormat.newBuilder()
                  .setVersion(1)
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                  .build()
                  .toByteString()),
          // Invalid type url for ML_DSA_87
          ProtoParametersSerialization.create(
              PUBLIC_TYPE_URL,
              OutputPrefixType.RAW,
              MlDsaKeyFormat.newBuilder()
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                  .build()
                  .toByteString()));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  @DataPoints("invalidParametersSerializations")
  public static final List<ProtoParametersSerialization> invalidParametersSerializations =
      createInvalidParameters();

  @Theory
  public void parseInvalidParameters_throws(
      @FromDataPoints("invalidParametersSerializations") ProtoParametersSerialization serialization)
      throws Exception {
    assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
  }

  @DataPoints("invalidPublicKeySerializations")
  public static final List<ProtoKeySerialization> invalidPublicKeySerializations =
      createInvalidPublicKeySerializations();

  private static List<ProtoKeySerialization> createInvalidPublicKeySerializations() {
    try {
      return Arrays.asList(
          // Invalid type url (which will cause the wrong parser being invoked, and that parser will
          // not accept this proto)
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                  .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Invalid version
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                  .setVersion(1)
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                  .setKeyValue(PUBLIC_KEY_ML_DSA_87_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Unknown instance
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(
                              com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_UNKNOWN_INSTANCE))
                  .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Wrong key value
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(
                              com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_UNKNOWN_INSTANCE))
                  .setKeyValue(PUBLIC_KEY_ML_DSA_87_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Invalid proto serialization
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              ByteString.copyFrom(new byte[] {(byte) 0x80}),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Wrong key material type
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                  .setKeyValue(PUBLIC_KEY_ML_DSA_87_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Unknown output prefix type
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(
                              com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_UNKNOWN_INSTANCE))
                  .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.CRUNCHY,
              /* idRequirement= */ 42));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  @Theory
  public void parseInvalidPublicKeySerialization_throws(
      @FromDataPoints("invalidPublicKeySerializations") ProtoKeySerialization serialization)
      throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }

  @DataPoints("invalidPrivateKeySerializations")
  public static final List<ProtoKeySerialization> invalidPrivateKeySerializations =
      createInvalidPrivateKeySerializations();

  private static List<ProtoKeySerialization> createInvalidPrivateKeySerializations() {
    try {
      return Arrays.asList(
          // Invalid type url (which will cause the wrong parser being invoked, and that parser will
          // not accept this proto)
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                  .setPublicKey(
                      com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                          .setParams(
                              MlDsaParams.newBuilder()
                                  .setMlDsaInstance(
                                      com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                          .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING))
                  .setKeyValue(PRIVATE_KEY_ML_DSA_65_SEED_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Invalid version
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                  .setVersion(1)
                  .setPublicKey(
                      com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                          .setParams(
                              MlDsaParams.newBuilder()
                                  .setMlDsaInstance(
                                      com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                          .setKeyValue(PUBLIC_KEY_ML_DSA_87_BYTE_STRING))
                  .setKeyValue(PRIVATE_KEY_ML_DSA_87_SEED_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Public key invalid version
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                  .setPublicKey(
                      com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                          .setVersion(1)
                          .setParams(
                              MlDsaParams.newBuilder()
                                  .setMlDsaInstance(
                                      com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                          .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING))
                  .setKeyValue(PRIVATE_KEY_ML_DSA_65_SEED_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Unknown instance in public key
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                  .setPublicKey(
                      com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                          .setParams(
                              MlDsaParams.newBuilder()
                                  .setMlDsaInstance(
                                      com.google.crypto.tink.proto.MlDsaInstance
                                          .ML_DSA_UNKNOWN_INSTANCE))
                          .setKeyValue(PUBLIC_KEY_ML_DSA_87_BYTE_STRING))
                  .setKeyValue(PRIVATE_KEY_ML_DSA_87_SEED_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Invalid proto serialization
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              ByteString.copyFrom(new byte[] {(byte) 0x80}),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Invalid private seed value
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                  .setPublicKey(
                      com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                          .setParams(
                              MlDsaParams.newBuilder()
                                  .setMlDsaInstance(
                                      com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                          .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING))
                  .setKeyValue(ByteString.copyFrom(new byte[] {(byte) 0x80}))
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Invalid key material type
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                  .setPublicKey(
                      com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                          .setParams(
                              MlDsaParams.newBuilder()
                                  .setMlDsaInstance(
                                      com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                          .setKeyValue(PUBLIC_KEY_ML_DSA_87_BYTE_STRING))
                  .setKeyValue(PRIVATE_KEY_ML_DSA_87_SEED_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Invalid output prefix type
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                  .setPublicKey(
                      com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                          .setParams(
                              MlDsaParams.newBuilder()
                                  .setMlDsaInstance(
                                      com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                          .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING))
                  .setKeyValue(PRIVATE_KEY_ML_DSA_65_SEED_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.CRUNCHY,
              /* idRequirement= */ 42));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  @Theory
  public void parseInvalidPrivateKeySerialization_throws(
      @FromDataPoints("invalidPrivateKeySerializations") ProtoKeySerialization serialization)
      throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }
}
