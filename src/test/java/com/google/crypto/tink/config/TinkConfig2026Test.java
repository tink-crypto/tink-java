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

package com.google.crypto.tink.config;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.ProtoKeySerializer;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.daead.PredefinedDeterministicAeadParameters;
import com.google.crypto.tink.hybrid.PredefinedHybridParameters;
import com.google.crypto.tink.jwt.JwtEcdsaParameters;
import com.google.crypto.tink.jwt.JwtHmacParameters;
import com.google.crypto.tink.jwt.JwtMac;
import com.google.crypto.tink.jwt.JwtPublicKeySign;
import com.google.crypto.tink.jwt.JwtPublicKeyVerify;
import com.google.crypto.tink.jwt.JwtValidator;
import com.google.crypto.tink.jwt.RawJwt;
import com.google.crypto.tink.jwt.VerifiedJwt;
import com.google.crypto.tink.keyderivation.KeysetDeriver;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationParameters;
import com.google.crypto.tink.mac.ChunkedMac;
import com.google.crypto.tink.mac.ChunkedMacComputation;
import com.google.crypto.tink.mac.ChunkedMacVerification;
import com.google.crypto.tink.mac.PredefinedMacParameters;
import com.google.crypto.tink.prf.HkdfPrfParameters;
import com.google.crypto.tink.prf.PrfSet;
import com.google.crypto.tink.signature.PredefinedSignatureParameters;
import com.google.crypto.tink.streamingaead.PredefinedStreamingAeadParameters;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link TinkConfig2026}. */
@RunWith(JUnit4.class)
public class TinkConfig2026Test {

  @Test
  public void get_returnsNonNull() {
    assertThat(TinkConfig2026.get()).isNotNull();
  }

  @Test
  public void getOrNull_protoKeySerializer_returnsNonNull() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    Configuration config = TinkConfig2026.get();
    assertThat(config.getOrNull(ProtoKeySerializer.class)).isNotNull();
  }

  @Test
  public void getOrNull_unregisteredClass_returnsNull() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    Configuration config = TinkConfig2026.get();
    assertThat(config.getOrNull(String.class)).isNull();
  }

  @Test
  public void aead_works() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    Configuration config = TinkConfig2026.get();
    Parameters parameters = PredefinedAeadParameters.AES128_GCM;

    // Keyset generation
    KeysetHandle handle = KeysetHandle.generateNew(parameters, config);
    assertThat(handle.getPrimary().getKey().getParameters()).isEqualTo(parameters);

    // Serialization & Parsing
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get(), config);
    KeysetHandle parsedHandle =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get(), config);
    assertThat(parsedHandle.equalsKeyset(handle)).isTrue();

    byte[] serializedParams = TinkProtoParametersFormat.serialize(parameters, config);
    Parameters parsedParams = TinkProtoParametersFormat.parse(serializedParams, config);
    assertThat(parsedParams).isEqualTo(parameters);

    // Primitive creation & execution
    Aead aead = handle.getPrimitive(config, Aead.class);
    byte[] plaintext = "hello".getBytes(UTF_8);
    byte[] associatedData = "data".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
  }

  @Test
  public void deterministicAead_works() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    Configuration config = TinkConfig2026.get();
    Parameters parameters = PredefinedDeterministicAeadParameters.AES256_SIV;

    // Keyset generation
    KeysetHandle handle = KeysetHandle.generateNew(parameters, config);
    assertThat(handle.getPrimary().getKey().getParameters()).isEqualTo(parameters);

    // Serialization & Parsing
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get(), config);
    KeysetHandle parsedHandle =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get(), config);
    assertThat(parsedHandle.equalsKeyset(handle)).isTrue();

    byte[] serializedParams = TinkProtoParametersFormat.serialize(parameters, config);
    Parameters parsedParams = TinkProtoParametersFormat.parse(serializedParams, config);
    assertThat(parsedParams).isEqualTo(parameters);

    // Primitive creation & execution
    DeterministicAead daead = handle.getPrimitive(config, DeterministicAead.class);
    byte[] plaintext = "hello".getBytes(UTF_8);
    byte[] associatedData = "data".getBytes(UTF_8);
    byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);
    assertThat(daead.decryptDeterministically(ciphertext, associatedData)).isEqualTo(plaintext);
  }

  @Test
  public void hybrid_works() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    Configuration config = TinkConfig2026.get();
    Parameters parameters = PredefinedHybridParameters.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM;

    // Keyset generation
    KeysetHandle privateHandle = KeysetHandle.generateNew(parameters, config);
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

    // Serialization & Parsing
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(privateHandle, InsecureSecretKeyAccess.get(), config);
    KeysetHandle parsedHandle =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get(), config);
    assertThat(parsedHandle.equalsKeyset(privateHandle)).isTrue();

    byte[] serializedParams = TinkProtoParametersFormat.serialize(parameters, config);
    Parameters parsedParams = TinkProtoParametersFormat.parse(serializedParams, config);
    assertThat(parsedParams).isEqualTo(parameters);

    // Primitive creation & execution
    HybridDecrypt decrypt = privateHandle.getPrimitive(config, HybridDecrypt.class);
    HybridEncrypt encrypt = publicHandle.getPrimitive(config, HybridEncrypt.class);
    byte[] plaintext = "hello".getBytes(UTF_8);
    byte[] contextInfo = "context".getBytes(UTF_8);
    byte[] ciphertext = encrypt.encrypt(plaintext, contextInfo);
    assertThat(decrypt.decrypt(ciphertext, contextInfo)).isEqualTo(plaintext);
  }

  @Test
  public void jwtMac_works() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    Configuration config = TinkConfig2026.get();
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(32)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();

    // Keyset generation
    KeysetHandle handle = KeysetHandle.generateNew(parameters, config);
    assertThat(handle.getPrimary().getKey().getParameters()).isEqualTo(parameters);

    // Serialization & Parsing
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get(), config);
    KeysetHandle parsedHandle =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get(), config);
    assertThat(parsedHandle.equalsKeyset(handle)).isTrue();

    byte[] serializedParams = TinkProtoParametersFormat.serialize(parameters, config);
    Parameters parsedParams = TinkProtoParametersFormat.parse(serializedParams, config);
    assertThat(parsedParams).isEqualTo(parameters);

    // Primitive creation & execution
    JwtMac jwtMac = handle.getPrimitive(config, JwtMac.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String compact = jwtMac.computeMacAndEncode(rawToken);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    VerifiedJwt verifiedToken = jwtMac.verifyMacAndDecode(compact, validator);
    assertThat(verifiedToken.getJwtId()).isEqualTo("jwtId");
  }

  @Test
  public void jwtSignature_works() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    Configuration config = TinkConfig2026.get();
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();

    // Keyset generation
    KeysetHandle privateHandle = KeysetHandle.generateNew(parameters, config);
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

    // Serialization & Parsing
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(privateHandle, InsecureSecretKeyAccess.get(), config);
    KeysetHandle parsedHandle =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get(), config);
    assertThat(parsedHandle.equalsKeyset(privateHandle)).isTrue();

    byte[] serializedParams = TinkProtoParametersFormat.serialize(parameters, config);
    Parameters parsedParams = TinkProtoParametersFormat.parse(serializedParams, config);
    assertThat(parsedParams).isEqualTo(parameters);

    // Primitive creation & execution
    JwtPublicKeySign signer = privateHandle.getPrimitive(config, JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier = publicHandle.getPrimitive(config, JwtPublicKeyVerify.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String compact = signer.signAndEncode(rawToken);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    VerifiedJwt verifiedToken = verifier.verifyAndDecode(compact, validator);
    assertThat(verifiedToken.getJwtId()).isEqualTo("jwtId");
  }

  @Test
  public void keyDerivation_works() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    Configuration config = TinkConfig2026.get();
    HkdfPrfParameters hkdfPrfParameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .build();
    AesGcmParameters derivedKeyParameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .build();
    PrfBasedKeyDerivationParameters parameters =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(hkdfPrfParameters)
            .setDerivedKeyParameters(derivedKeyParameters)
            .build();

    // Keyset generation
    KeysetHandle handle = KeysetHandle.generateNew(parameters, config);
    assertThat(handle.getPrimary().getKey().getParameters()).isEqualTo(parameters);

    // Serialization & Parsing
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get(), config);
    KeysetHandle parsedHandle =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get(), config);
    assertThat(parsedHandle.size()).isEqualTo(1);

    byte[] serializedParams = TinkProtoParametersFormat.serialize(parameters, config);
    Parameters parsedParams = TinkProtoParametersFormat.parse(serializedParams, config);
    assertThat(parsedParams).isEqualTo(parameters);

    // Primitive creation & execution
    KeysetDeriver deriver = handle.getPrimitive(config, KeysetDeriver.class);
    KeysetHandle derivedKeyset = deriver.deriveKeyset(new byte[] {1, 2, 3});
    assertThat(derivedKeyset.size()).isEqualTo(1);
    assertThat(derivedKeyset.getPrimary().getKey().getParameters()).isEqualTo(derivedKeyParameters);
  }

  @Test
  public void macAndChunkedMac_works() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    Configuration config = TinkConfig2026.get();
    Parameters parameters = PredefinedMacParameters.HMAC_SHA256_128BITTAG;

    // Keyset generation
    KeysetHandle handle = KeysetHandle.generateNew(parameters, config);
    assertThat(handle.getPrimary().getKey().getParameters()).isEqualTo(parameters);

    // Serialization & Parsing
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get(), config);
    KeysetHandle parsedHandle =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get(), config);
    assertThat(parsedHandle.equalsKeyset(handle)).isTrue();

    byte[] serializedParams = TinkProtoParametersFormat.serialize(parameters, config);
    Parameters parsedParams = TinkProtoParametersFormat.parse(serializedParams, config);
    assertThat(parsedParams).isEqualTo(parameters);

    // Mac primitive
    Mac mac = handle.getPrimitive(config, Mac.class);
    byte[] data = "hello".getBytes(UTF_8);
    byte[] tag = mac.computeMac(data);
    mac.verifyMac(tag, data);

    // ChunkedMac primitive
    ChunkedMac chunkedMac = handle.getPrimitive(config, ChunkedMac.class);
    ChunkedMacComputation computation = chunkedMac.createComputation();
    computation.update(ByteBuffer.wrap(data));
    byte[] chunkedTag = computation.computeMac();
    ChunkedMacVerification verification = chunkedMac.createVerification(chunkedTag);
    verification.update(ByteBuffer.wrap(data));
    verification.verifyMac();
  }

  @Test
  public void prf_works() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    Configuration config = TinkConfig2026.get();
    HkdfPrfParameters parameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .build();

    // Keyset generation
    KeysetHandle handle = KeysetHandle.generateNew(parameters, config);
    assertThat(handle.getPrimary().getKey().getParameters()).isEqualTo(parameters);

    // Serialization & Parsing
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get(), config);
    KeysetHandle parsedHandle =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get(), config);
    assertThat(parsedHandle.equalsKeyset(handle)).isTrue();

    byte[] serializedParams = TinkProtoParametersFormat.serialize(parameters, config);
    Parameters parsedParams = TinkProtoParametersFormat.parse(serializedParams, config);
    assertThat(parsedParams).isEqualTo(parameters);

    // Primitive creation & execution
    PrfSet prfSet = handle.getPrimitive(config, PrfSet.class);
    byte[] output = prfSet.computePrimary("message".getBytes(UTF_8), 16);
    assertThat(output).hasLength(16);
  }

  @Test
  public void signature_works() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    Configuration config = TinkConfig2026.get();
    Parameters parameters = PredefinedSignatureParameters.ECDSA_P256;

    // Keyset generation
    KeysetHandle privateHandle = KeysetHandle.generateNew(parameters, config);
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

    // Serialization & Parsing
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(privateHandle, InsecureSecretKeyAccess.get(), config);
    KeysetHandle parsedHandle =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get(), config);
    assertThat(parsedHandle.equalsKeyset(privateHandle)).isTrue();

    byte[] serializedParams = TinkProtoParametersFormat.serialize(parameters, config);
    Parameters parsedParams = TinkProtoParametersFormat.parse(serializedParams, config);
    assertThat(parsedParams).isEqualTo(parameters);

    // Primitive creation & execution
    PublicKeySign signer = privateHandle.getPrimitive(config, PublicKeySign.class);
    PublicKeyVerify verifier = publicHandle.getPrimitive(config, PublicKeyVerify.class);
    byte[] message = "hello".getBytes(UTF_8);
    byte[] signature = signer.sign(message);
    verifier.verify(signature, message);
  }

  @Test
  public void streamingAead_works() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    Configuration config = TinkConfig2026.get();
    Parameters parameters = PredefinedStreamingAeadParameters.AES128_GCM_HKDF_4KB;

    // Keyset generation
    KeysetHandle handle = KeysetHandle.generateNew(parameters, config);
    assertThat(handle.getPrimary().getKey().getParameters()).isEqualTo(parameters);

    // Serialization & Parsing
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get(), config);
    KeysetHandle parsedHandle =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get(), config);
    assertThat(parsedHandle.equalsKeyset(handle)).isTrue();

    byte[] serializedParams = TinkProtoParametersFormat.serialize(parameters, config);
    Parameters parsedParams = TinkProtoParametersFormat.parse(serializedParams, config);
    assertThat(parsedParams).isEqualTo(parameters);

    // Primitive creation & execution
    StreamingAead streamingAead = handle.getPrimitive(config, StreamingAead.class);
    byte[] plaintext = "hello streaming world".getBytes(UTF_8);
    byte[] associatedData = "associated".getBytes(UTF_8);

    ByteArrayOutputStream ciphertextStream = new ByteArrayOutputStream();
    try (OutputStream encryptingStream =
        streamingAead.newEncryptingStream(ciphertextStream, associatedData)) {
      encryptingStream.write(plaintext);
    }
    byte[] ciphertext = ciphertextStream.toByteArray();

    ByteArrayInputStream inputStream = new ByteArrayInputStream(ciphertext);
    byte[] decrypted = new byte[plaintext.length];
    try (InputStream decryptingStream =
        streamingAead.newDecryptingStream(inputStream, associatedData)) {
      int bytesRead = decryptingStream.read(decrypted);
      assertThat(bytesRead).isEqualTo(plaintext.length);
    }
    assertThat(decrypted).isEqualTo(plaintext);
  }
}
