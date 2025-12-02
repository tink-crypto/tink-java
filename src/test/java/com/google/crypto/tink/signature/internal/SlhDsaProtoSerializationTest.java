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

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.proto.SlhDsaKeyFormat;
import com.google.crypto.tink.proto.SlhDsaParams;
import com.google.crypto.tink.signature.SlhDsaParameters;
import com.google.crypto.tink.signature.SlhDsaParameters.Variant;
import com.google.crypto.tink.signature.SlhDsaPrivateKey;
import com.google.crypto.tink.signature.SlhDsaPublicKey;
import com.google.crypto.tink.subtle.Hex;
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

@RunWith(Theories.class)
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public class SlhDsaProtoSerializationTest {

  private static final String PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey";
  private static final String PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.SlhDsaPublicKey";

  // Test case from tink/go/internal/signature/slhdsa/slhdsa_kat_vectors_test.go
  private static final String SLH_DSA_SHA2_128S_PUBLIC_KEY_HEX =
      "66e94bff8074e57fb66e9627596140df21f975f9c51286d8198ba57ddd099321";
  private static final byte[] slhDsaSha2128SPublicKeyByteArray = Hex.decode(SLH_DSA_SHA2_128S_PUBLIC_KEY_HEX);
  private static final Bytes SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES = Bytes.copyFrom(slhDsaSha2128SPublicKeyByteArray);
  private static final ByteString SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTE_STRING =
      ByteString.copyFrom(slhDsaSha2128SPublicKeyByteArray);

  private static final String SLH_DSA_SHA2_128S_PRIVATE_KEY_HEX =
      "5b13979e405179ea3c7b250ddf5637bc081990d028080b35f09b1db79bd9083d66e94bff8074e57fb66e9627596140df21f975f9c51286d8198ba57ddd099321";
  private static final byte[] slhDsaSha2128SPrivateKeyByteArray = Hex.decode(SLH_DSA_SHA2_128S_PRIVATE_KEY_HEX);
  private static final SecretBytes SLH_DSA_SHA2_128S_PRIVATE_KEY_BYTES =
      SecretBytes.copyFrom(slhDsaSha2128SPrivateKeyByteArray, InsecureSecretKeyAccess.get());
  private static final ByteString SLH_DSA_SHA2_128S_PRIVATE_KEY_BYTE_STRING =
      ByteString.copyFrom(slhDsaSha2128SPrivateKeyByteArray);

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  @BeforeClass
  public static void setUp() throws Exception {
    SlhDsaProtoSerialization.register(registry);
  }

  // Parameters correctness tests.
  private static final class ParametersSerializationTestPair {
    final SlhDsaParameters parameters;
    final ProtoParametersSerialization serialization;

    ParametersSerializationTestPair(
        SlhDsaParameters parameters, ProtoParametersSerialization serialization) {
      this.parameters = parameters;
      this.serialization = serialization;
    }
  }

  @DataPoints("parametersSerializationTestPairList")
  public static final List<ParametersSerializationTestPair> parametersSerializationTestPairList =
      Arrays.asList(
          new ParametersSerializationTestPair(
              SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.NO_PREFIX),
              ProtoParametersSerialization.create(
                  PRIVATE_TYPE_URL,
                  OutputPrefixType.RAW,
                  SlhDsaKeyFormat.newBuilder()
                      .setParams(
                          SlhDsaParams.newBuilder()
                              .setKeySize(SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES)
                              .setHashType(com.google.crypto.tink.proto.SlhDsaHashType.SHA2)
                              .setSigType(
                                  com.google.crypto.tink.proto.SlhDsaSignatureType.SMALL_SIGNATURE))
                      .build())),
          new ParametersSerializationTestPair(
              SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.TINK),
              ProtoParametersSerialization.create(
                  PRIVATE_TYPE_URL,
                  OutputPrefixType.TINK,
                  SlhDsaKeyFormat.newBuilder()
                      .setParams(
                          SlhDsaParams.newBuilder()
                              .setKeySize(SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES)
                              .setHashType(com.google.crypto.tink.proto.SlhDsaHashType.SHA2)
                              .setSigType(
                                  com.google.crypto.tink.proto.SlhDsaSignatureType.SMALL_SIGNATURE))
                      .build())));

  @Theory
  public void serializeParseParameters_equal(
      @FromDataPoints("parametersSerializationTestPairList") ParametersSerializationTestPair pair)
      throws Exception {
    ProtoParametersSerialization serialized =
        registry.serializeParameters(pair.parameters, ProtoParametersSerialization.class);
    Parameters parsed = registry.parseParameters(pair.serialization);

    assertEqualWhenValueParsed(SlhDsaKeyFormat.parser(), serialized, pair.serialization);
    assertThat(parsed).isEqualTo(pair.parameters);
  }

  // Public key correctness tests.
  private static final class PublicKeySerializationTestPair {
    final SlhDsaPublicKey key;
    final ProtoKeySerialization serialization;

    PublicKeySerializationTestPair(SlhDsaPublicKey key, ProtoKeySerialization serialization) {
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
              SlhDsaPublicKey.builder()
                  .setParameters(SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.NO_PREFIX))
                  .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
                  .build(),
              ProtoKeySerialization.create(
                  PUBLIC_TYPE_URL,
                  com.google.crypto.tink.proto.SlhDsaPublicKey.newBuilder()
                      .setParams(
                          SlhDsaParams.newBuilder()
                              .setKeySize(SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES)
                              .setHashType(com.google.crypto.tink.proto.SlhDsaHashType.SHA2)
                              .setSigType(
                                  com.google.crypto.tink.proto.SlhDsaSignatureType.SMALL_SIGNATURE))
                      .setKeyValue(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTE_STRING)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PUBLIC,
                  OutputPrefixType.RAW,
                  /* idRequirement= */ null)),
          new PublicKeySerializationTestPair(
              SlhDsaPublicKey.builder()
                  .setParameters(SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.TINK))
                  .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
                  .setIdRequirement(0x12345678)
                  .build(),
              ProtoKeySerialization.create(
                  PUBLIC_TYPE_URL,
                  com.google.crypto.tink.proto.SlhDsaPublicKey.newBuilder()
                      .setParams(
                          SlhDsaParams.newBuilder()
                              .setKeySize(SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES)
                              .setHashType(com.google.crypto.tink.proto.SlhDsaHashType.SHA2)
                              .setSigType(
                                  com.google.crypto.tink.proto.SlhDsaSignatureType.SMALL_SIGNATURE))
                      .setKeyValue(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTE_STRING)
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
    ProtoKeySerialization serialized =
        registry.serializeKey(pair.key, ProtoKeySerialization.class, null);
    Key parsed = registry.parseKey(pair.serialization, null);

    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.SlhDsaPublicKey.parser(), serialized, pair.serialization);
    assertTrue(parsed.equalsKey(pair.key));
  }

  // Private key correctness tests.
  private static final class PrivateKeySerializationTestPair {
    final SlhDsaPrivateKey key;
    final ProtoKeySerialization serialization;

    PrivateKeySerializationTestPair(SlhDsaPrivateKey key, ProtoKeySerialization serialization) {
      this.key = key;
      this.serialization = serialization;
    }
  }

  @DataPoints("privateKeySerializationTestPairList")
  public static final List<PrivateKeySerializationTestPair> privateKeySerializationTestPairList =
      createPrivateKeySerializationTestPairs();

  private static List<PrivateKeySerializationTestPair> createPrivateKeySerializationTestPairs() {
    try {
      SlhDsaPublicKey noPrefixPublicKey =
          SlhDsaPublicKey.builder()
              .setParameters(SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.NO_PREFIX))
              .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
              .build();
      SlhDsaPublicKey tinkPublicKey =
          SlhDsaPublicKey.builder()
              .setParameters(SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.TINK))
              .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
              .setIdRequirement(0x12345678)
              .build();
      return Arrays.asList(
          new PrivateKeySerializationTestPair(
              SlhDsaPrivateKey.createWithoutVerification(
                  noPrefixPublicKey, SLH_DSA_SHA2_128S_PRIVATE_KEY_BYTES),
              ProtoKeySerialization.create(
                  PRIVATE_TYPE_URL,
                  com.google.crypto.tink.proto.SlhDsaPrivateKey.newBuilder()
                      .setPublicKey(
                          com.google.crypto.tink.proto.SlhDsaPublicKey.newBuilder()
                              .setParams(
                                  SlhDsaParams.newBuilder()
                                      .setKeySize(SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES)
                                      .setHashType(
                                          com.google.crypto.tink.proto.SlhDsaHashType.SHA2)
                                      .setSigType(
                                          com.google.crypto.tink.proto.SlhDsaSignatureType
                                              .SMALL_SIGNATURE))
                              .setKeyValue(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTE_STRING))
                      .setKeyValue(SLH_DSA_SHA2_128S_PRIVATE_KEY_BYTE_STRING)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PRIVATE,
                  OutputPrefixType.RAW,
                  /* idRequirement= */ null)),
          new PrivateKeySerializationTestPair(
              SlhDsaPrivateKey.createWithoutVerification(
                  tinkPublicKey, SLH_DSA_SHA2_128S_PRIVATE_KEY_BYTES),
              ProtoKeySerialization.create(
                  PRIVATE_TYPE_URL,
                  com.google.crypto.tink.proto.SlhDsaPrivateKey.newBuilder()
                      .setPublicKey(
                          com.google.crypto.tink.proto.SlhDsaPublicKey.newBuilder()
                              .setParams(
                                  SlhDsaParams.newBuilder()
                                      .setKeySize(SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES)
                                      .setHashType(
                                          com.google.crypto.tink.proto.SlhDsaHashType.SHA2)
                                      .setSigType(
                                          com.google.crypto.tink.proto.SlhDsaSignatureType
                                              .SMALL_SIGNATURE))
                              .setKeyValue(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTE_STRING))
                      .setKeyValue(SLH_DSA_SHA2_128S_PRIVATE_KEY_BYTE_STRING)
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
        registry.serializeKey(pair.key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    Key parsed = registry.parseKey(pair.serialization, InsecureSecretKeyAccess.get());

    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.SlhDsaPrivateKey.parser(), serialized, pair.serialization);
    assertTrue(parsed.equalsKey(pair.key));
  }

  // Test failure modes
  @Test
  public void serializePrivateKeyWithoutAccess_throws() throws Exception {
    SlhDsaPrivateKey privateKey = privateKeySerializationTestPairList.get(0).key;
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.serializeKey(privateKey, ProtoKeySerialization.class, /* access= */ null));
  }

  @Test
  public void parsePrivateKeyWithoutAccess_throws() throws Exception {
    ProtoKeySerialization serialization = privateKeySerializationTestPairList.get(0).serialization;
    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }

  @DataPoints("invalidParametersSerializations")
  public static final List<ProtoParametersSerialization> invalidParametersSerializations =
      Arrays.asList(
          // Unknown output prefix
          ProtoParametersSerialization.create(
              PRIVATE_TYPE_URL,
              OutputPrefixType.UNKNOWN_PREFIX,
              SlhDsaKeyFormat.newBuilder()
                  .setParams(
                      SlhDsaParams.newBuilder()
                          .setKeySize(SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES)
                          .setHashType(com.google.crypto.tink.proto.SlhDsaHashType.SHA2)
                          .setSigType(
                              com.google.crypto.tink.proto.SlhDsaSignatureType.SMALL_SIGNATURE))
                  .build()),
          // Invalid version
          ProtoParametersSerialization.create(
              PRIVATE_TYPE_URL,
              OutputPrefixType.RAW,
              SlhDsaKeyFormat.newBuilder()
                  .setVersion(1)
                  .setParams(
                      SlhDsaParams.newBuilder()
                          .setKeySize(SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES)
                          .setHashType(com.google.crypto.tink.proto.SlhDsaHashType.SHA2)
                          .setSigType(
                              com.google.crypto.tink.proto.SlhDsaSignatureType.SMALL_SIGNATURE))
                  .build()),
          // Unsupported key size
          ProtoParametersSerialization.create(
              PRIVATE_TYPE_URL,
              OutputPrefixType.RAW,
              SlhDsaKeyFormat.newBuilder()
                  .setParams(
                      SlhDsaParams.newBuilder()
                          .setKeySize(256)
                          .setHashType(com.google.crypto.tink.proto.SlhDsaHashType.SHA2)
                          .setSigType(
                              com.google.crypto.tink.proto.SlhDsaSignatureType.SMALL_SIGNATURE))
                  .build()),
          // Invalid proto serialization
          ProtoParametersSerialization.create(
              KeyTemplate.newBuilder()
                  .setTypeUrl(PRIVATE_TYPE_URL)
                  .setOutputPrefixType(OutputPrefixType.RAW)
                  .setValue(ByteString.copyFrom(new byte[] {(byte) 0x80}))
                  .build()),
          // Invalid type url (which will cause the wrong parser being invoked, and that parser will
          // not accept this proto)
          ProtoParametersSerialization.create(
              PUBLIC_TYPE_URL,
              OutputPrefixType.RAW,
              SlhDsaKeyFormat.newBuilder()
                  .setParams(
                      SlhDsaParams.newBuilder()
                          .setKeySize(SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES)
                          .setHashType(com.google.crypto.tink.proto.SlhDsaHashType.SHA2)
                          .setSigType(
                              com.google.crypto.tink.proto.SlhDsaSignatureType.SMALL_SIGNATURE))
                  .build()));

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
              com.google.crypto.tink.proto.SlhDsaPublicKey.newBuilder()
                  .setParams(
                      SlhDsaParams.newBuilder()
                          .setKeySize(SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES)
                          .setHashType(com.google.crypto.tink.proto.SlhDsaHashType.SHA2)
                          .setSigType(
                              com.google.crypto.tink.proto.SlhDsaSignatureType.SMALL_SIGNATURE))
                  .setKeyValue(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Invalid version
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              com.google.crypto.tink.proto.SlhDsaPublicKey.newBuilder()
                  .setVersion(1)
                  .setParams(
                      SlhDsaParams.newBuilder()
                          .setKeySize(SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES)
                          .setHashType(com.google.crypto.tink.proto.SlhDsaHashType.SHA2)
                          .setSigType(
                              com.google.crypto.tink.proto.SlhDsaSignatureType.SMALL_SIGNATURE))
                  .setKeyValue(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Wrong key value size
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              com.google.crypto.tink.proto.SlhDsaPublicKey.newBuilder()
                  .setParams(
                      SlhDsaParams.newBuilder()
                          .setKeySize(SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES)
                          .setHashType(com.google.crypto.tink.proto.SlhDsaHashType.SHA2)
                          .setSigType(
                              com.google.crypto.tink.proto.SlhDsaSignatureType.SMALL_SIGNATURE))
                  .setKeyValue(ByteString.copyFromUtf8("wrong key value size"))
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
              com.google.crypto.tink.proto.SlhDsaPublicKey.newBuilder()
                  .setParams(
                      SlhDsaParams.newBuilder()
                          .setKeySize(SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES)
                          .setHashType(com.google.crypto.tink.proto.SlhDsaHashType.SHA2)
                          .setSigType(
                              com.google.crypto.tink.proto.SlhDsaSignatureType.SMALL_SIGNATURE))
                  .setKeyValue(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Unknown output prefix type
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              com.google.crypto.tink.proto.SlhDsaPublicKey.newBuilder()
                  .setParams(
                      SlhDsaParams.newBuilder()
                          .setKeySize(SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES)
                          .setHashType(com.google.crypto.tink.proto.SlhDsaHashType.SHA2)
                          .setSigType(
                              com.google.crypto.tink.proto.SlhDsaSignatureType.SMALL_SIGNATURE))
                  .setKeyValue(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTE_STRING)
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
              com.google.crypto.tink.proto.SlhDsaPrivateKey.newBuilder()
                  .setPublicKey(
                      com.google.crypto.tink.proto.SlhDsaPublicKey.newBuilder()
                          .setParams(
                              SlhDsaParams.newBuilder()
                                  .setKeySize(SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES)
                                  .setHashType(com.google.crypto.tink.proto.SlhDsaHashType.SHA2)
                                  .setSigType(
                                      com.google.crypto.tink.proto.SlhDsaSignatureType
                                          .SMALL_SIGNATURE))
                          .setKeyValue(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTE_STRING))
                  .setKeyValue(SLH_DSA_SHA2_128S_PRIVATE_KEY_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Invalid version
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.SlhDsaPrivateKey.newBuilder()
                  .setVersion(1)
                  .setPublicKey(
                      com.google.crypto.tink.proto.SlhDsaPublicKey.newBuilder()
                          .setParams(
                              SlhDsaParams.newBuilder()
                                  .setKeySize(SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES)
                                  .setHashType(com.google.crypto.tink.proto.SlhDsaHashType.SHA2)
                                  .setSigType(
                                      com.google.crypto.tink.proto.SlhDsaSignatureType
                                          .SMALL_SIGNATURE))
                          .setKeyValue(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTE_STRING))
                  .setKeyValue(SLH_DSA_SHA2_128S_PRIVATE_KEY_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Public key invalid version
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.SlhDsaPrivateKey.newBuilder()
                  .setPublicKey(
                      com.google.crypto.tink.proto.SlhDsaPublicKey.newBuilder()
                          .setVersion(1)
                          .setParams(
                              SlhDsaParams.newBuilder()
                                  .setKeySize(SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES)
                                  .setHashType(com.google.crypto.tink.proto.SlhDsaHashType.SHA2)
                                  .setSigType(
                                      com.google.crypto.tink.proto.SlhDsaSignatureType
                                          .SMALL_SIGNATURE))
                          .setKeyValue(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTE_STRING))
                  .setKeyValue(SLH_DSA_SHA2_128S_PRIVATE_KEY_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Unsupported key size in public key
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.SlhDsaPrivateKey.newBuilder()
                  .setPublicKey(
                      com.google.crypto.tink.proto.SlhDsaPublicKey.newBuilder()
                          .setParams(
                              SlhDsaParams.newBuilder()
                                  .setKeySize(256)
                                  .setHashType(com.google.crypto.tink.proto.SlhDsaHashType.SHA2)
                                  .setSigType(
                                      com.google.crypto.tink.proto.SlhDsaSignatureType
                                          .SMALL_SIGNATURE))
                          .setKeyValue(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTE_STRING))
                  .setKeyValue(SLH_DSA_SHA2_128S_PRIVATE_KEY_BYTE_STRING)
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
          // Invalid private key bytes size
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.SlhDsaPrivateKey.newBuilder()
                  .setPublicKey(
                      com.google.crypto.tink.proto.SlhDsaPublicKey.newBuilder()
                          .setParams(
                              SlhDsaParams.newBuilder()
                                  .setKeySize(SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES)
                                  .setHashType(com.google.crypto.tink.proto.SlhDsaHashType.SHA2)
                                  .setSigType(
                                      com.google.crypto.tink.proto.SlhDsaSignatureType
                                          .SMALL_SIGNATURE))
                          .setKeyValue(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTE_STRING))
                  .setKeyValue(ByteString.copyFrom(new byte[] {(byte) 0x80}))
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Invalid key material type
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.SlhDsaPrivateKey.newBuilder()
                  .setPublicKey(
                      com.google.crypto.tink.proto.SlhDsaPublicKey.newBuilder()
                          .setParams(
                              SlhDsaParams.newBuilder()
                                  .setKeySize(SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES)
                                  .setHashType(com.google.crypto.tink.proto.SlhDsaHashType.SHA2)
                                  .setSigType(
                                      com.google.crypto.tink.proto.SlhDsaSignatureType
                                          .SMALL_SIGNATURE))
                          .setKeyValue(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTE_STRING))
                  .setKeyValue(SLH_DSA_SHA2_128S_PRIVATE_KEY_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Invalid output prefix type
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.SlhDsaPrivateKey.newBuilder()
                  .setPublicKey(
                      com.google.crypto.tink.proto.SlhDsaPublicKey.newBuilder()
                          .setParams(
                              SlhDsaParams.newBuilder()
                                  .setKeySize(SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES)
                                  .setHashType(com.google.crypto.tink.proto.SlhDsaHashType.SHA2)
                                  .setSigType(
                                      com.google.crypto.tink.proto.SlhDsaSignatureType
                                          .SMALL_SIGNATURE))
                          .setKeyValue(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTE_STRING))
                  .setKeyValue(SLH_DSA_SHA2_128S_PRIVATE_KEY_BYTE_STRING)
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
