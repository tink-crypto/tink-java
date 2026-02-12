// Copyright 2017 Google LLC
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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetReader;
import com.google.crypto.tink.PemKeyType;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.PemUtil;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.proto.EncryptedKeyset;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.annotation.Nullable;

/**
 * SignaturePemKeysetReader is a {@link KeysetReader} that can read digital signature keys in PEM
 * format (RFC 7468).
 *
 * <p>Only supports public keys.
 *
 * <p>Private, unknown or invalid keys are ignored.
 *
 * <h3>Usage</h3>
 *
 * <pre>{@code
 * import com.google.crypto.tink.PemKeyType;
 *
 * String pem = ...;
 * PemKeyType type = ...;
 * KeysetReader reader = SignaturePemKeysetReader.newBuilder().addPem(pem, type).build();
 * }</pre>
 */
public final class SignaturePemKeysetReader implements KeysetReader {
  // Exactly one of these two fields will be non-null.
  @Nullable
  private final Keyset keyset;
  @Nullable
  private final IOException exception;

  private SignaturePemKeysetReader(Keyset keyset, IOException exception) {
    if (keyset == null && exception == null) {
      throw new IllegalArgumentException("Exactly one of keyset and exception must be non-null.");
    }
    if (keyset != null && exception != null) {
      throw new IllegalArgumentException("Exactly one of keyset and exception must be non-null.");
    }
    this.keyset = keyset;
    this.exception = exception;
  }

  /** Returns a {@link Builder} for {@link SignaturePemKeysetReader}. */
  public static Builder newBuilder() {
    return new Builder();
  }

  /** Builder for SignaturePemKeysetReader */
  public static final class Builder {
    private List<PemKey> pemKeys = new ArrayList<PemKey>();

    Builder() {}

    // TODO(b/470859537): Make this public.
    private KeysetHandle buildKeysetHandle() throws GeneralSecurityException {
      KeysetHandle.Builder builder = KeysetHandle.newBuilder();
      for (PemKey pemKey : pemKeys) {
        BufferedReader reader = new BufferedReader(new StringReader(pemKey.pem));
        for (Key key = readKey(reader, pemKey.type);
            key != null;
            key = readKey(reader, pemKey.type)) {
          builder.addEntry(KeysetHandle.importKey(key).withRandomId());
        }
      }
      if (builder.size() == 0) {
        throw new GeneralSecurityException("cannot find any key");
      }
      builder.getAt(0).makePrimary();
      return builder.build();
    }

    public KeysetReader build() {
      Keyset keyset = null;
      IOException exception = null;
      try {
        KeysetHandle handle = buildKeysetHandle();
        byte[] bytes = TinkProtoKeysetFormat.serializeKeysetWithoutSecret(handle);
        keyset = Keyset.parseFrom(bytes, ExtensionRegistryLite.getEmptyRegistry());
      } catch (GeneralSecurityException e) {
        exception = new IOException(e);
      } catch (IOException e) {
        exception = e;
      }
      return new SignaturePemKeysetReader(keyset, exception);
    }

    /**
     * Adds a PEM.
     *
     * <p>A single PEM can contain multiple keys, but all must have the same {@code keyType}.
     * Invalid or unparsable keys are ignored.
     *
     * <p>The first key in the first added PEM is the primary key.
     */
    @CanIgnoreReturnValue
    public Builder addPem(String pem, PemKeyType keyType) {
      PemKey pemKey = new PemKey();
      pemKey.pem = pem;
      pemKey.type = keyType;
      pemKeys.add(pemKey);
      return this;
    }
  }

  private static final class PemKey {
    String pem;
    PemKeyType type;
  }

  @Override
  public Keyset read() throws IOException {
    if (exception != null) {
      throw exception;
    }
    return keyset;
  }

  @Override
  public EncryptedKeyset readEncrypted() throws IOException {
    throw new UnsupportedOperationException();
  }

  private static RSAPublicKey parseRsaPublicKey(X509EncodedKeySpec keySpec, int keySizeInBits) throws GeneralSecurityException  {
    KeyFactory rsaKeyFactory = EngineFactory.KEY_FACTORY.getInstance("RSA");
    RSAPublicKey rsaKey = (RSAPublicKey) rsaKeyFactory.generatePublic(keySpec);
    int foundKeySizeInBits = rsaKey.getModulus().bitLength();
    if (foundKeySizeInBits != keySizeInBits) {
      throw new GeneralSecurityException("wrong key size");
    }
    return rsaKey;
  }

  private static ECPublicKey parseEcPublicKey(X509EncodedKeySpec keySpec, int keySizeInBits) throws GeneralSecurityException {
    KeyFactory ecKeyFactory = EngineFactory.KEY_FACTORY.getInstance("EC");
    ECPublicKey ecKey = (ECPublicKey) ecKeyFactory.generatePublic(keySpec);

    ECParameterSpec ecParams = ecKey.getParams();
    if (!EllipticCurves.isNistEcParameterSpec(ecParams)) {
      throw new GeneralSecurityException("EC key is not a NIST curve");
    }
    int foundKeySizeInBits = EllipticCurves.fieldSizeInBits(ecParams.getCurve());
    if (foundKeySizeInBits != keySizeInBits) {
      throw new GeneralSecurityException("wrong key size");
    }
    return ecKey;
  }

  /** Reads a single PEM key from {@code reader}. Invalid or unparsable PEM are ignored. */
  @Nullable
  private static Key readKey(BufferedReader reader, PemKeyType pemKeyType) {
    try {
      return readKeyWithExceptions(reader, pemKeyType);
    } catch (GeneralSecurityException e) {
      return null;
    }
  }

  /** Reads a single PEM key from {@code reader}. Throws an exception if parsing fails. */
  private static Key readKeyWithExceptions(BufferedReader reader, PemKeyType pemKeyType)
      throws GeneralSecurityException {
    EncodedKeySpec keySpec = PemUtil.parsePemToKeySpec(reader);
    if (keySpec == null) {
      throw new GeneralSecurityException("cannot parse PEM key");
    }
    if (!(keySpec instanceof X509EncodedKeySpec)) {
      throw new GeneralSecurityException("PEM key is not a public key");
    }
    X509EncodedKeySpec x509KeySpec = (X509EncodedKeySpec) keySpec;

    switch (pemKeyType) {
      case RSA_SIGN_PKCS1_2048_SHA256:
      case RSA_SIGN_PKCS1_3072_SHA256:
      case RSA_SIGN_PKCS1_4096_SHA256:
      case RSA_SIGN_PKCS1_4096_SHA512:
        return convertRsaSsaPkcs1PublicKey(pemKeyType, x509KeySpec);
      case RSA_PSS_2048_SHA256:
      case RSA_PSS_3072_SHA256:
      case RSA_PSS_4096_SHA256:
      case RSA_PSS_4096_SHA512:
        return convertRsaSsaPssPublicKey(pemKeyType, x509KeySpec);
      case ECDSA_P256_SHA256:
      case ECDSA_P384_SHA384:
      case ECDSA_P521_SHA512:
        return convertEcdsaPublicKey(pemKeyType, x509KeySpec);
      case ED25519:
        return convertEd25519PublicKey(x509KeySpec);
      case ML_DSA_65:
        return convertMlDsa65PublicKey(x509KeySpec);
      default:
        throw new IllegalArgumentException("unsupported key type: " + pemKeyType);
    }
  }

  private static RsaSsaPkcs1Parameters getRsaPkcs1Parameters(PemKeyType pemKeyType)
      throws GeneralSecurityException {
    switch (pemKeyType) {
      case RSA_SIGN_PKCS1_2048_SHA256:
        return RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
      case RSA_SIGN_PKCS1_3072_SHA256:
        return RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(3072)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
      case RSA_SIGN_PKCS1_4096_SHA256:
        return RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
      case RSA_SIGN_PKCS1_4096_SHA512:
        return RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA512)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
      default:
        throw new IllegalArgumentException("unsupported RSA PKCS1 key type: " + pemKeyType);
    }
  }

  @AccessesPartialKey
  private static Key convertRsaSsaPkcs1PublicKey(PemKeyType pemKeyType, X509EncodedKeySpec keySpec)
      throws GeneralSecurityException {
    RSAPublicKey key = parseRsaPublicKey(keySpec, pemKeyType.keySizeInBits);
    return RsaSsaPkcs1PublicKey.builder()
        .setParameters(getRsaPkcs1Parameters(pemKeyType))
        .setModulus(key.getModulus())
        .build();
  }

  private static RsaSsaPssParameters getRsaPssParameters(PemKeyType pemKeyType)
      throws GeneralSecurityException {
    switch (pemKeyType) {
      case RSA_PSS_2048_SHA256:
        return RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
      case RSA_PSS_3072_SHA256:
        return RsaSsaPssParameters.builder()
            .setModulusSizeBits(3072)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
      case RSA_PSS_4096_SHA256:
        return RsaSsaPssParameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
      case RSA_PSS_4096_SHA512:
        return RsaSsaPssParameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA512)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA512)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(64)
            .build();
      default:
        throw new IllegalArgumentException("unsupported RSA PSS key type: " + pemKeyType);
    }
  }

  @AccessesPartialKey
  private static Key convertRsaSsaPssPublicKey(PemKeyType pemKeyType, X509EncodedKeySpec keySpec)
      throws GeneralSecurityException {
    RSAPublicKey key = parseRsaPublicKey(keySpec, pemKeyType.keySizeInBits);
    return RsaSsaPssPublicKey.builder()
        .setParameters(getRsaPssParameters(pemKeyType))
        .setModulus(key.getModulus())
        .build();
  }

  private static EcdsaParameters getEcdsaParameters(PemKeyType pemKeyType) throws GeneralSecurityException {
    switch (pemKeyType) {
      case ECDSA_P256_SHA256:
        return
            EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
      case ECDSA_P384_SHA384:
        return EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
            .setCurveType(EcdsaParameters.CurveType.NIST_P384)
            .setHashType(EcdsaParameters.HashType.SHA384)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
      case ECDSA_P521_SHA512:
        return EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
            .setCurveType(EcdsaParameters.CurveType.NIST_P521)
            .setHashType(EcdsaParameters.HashType.SHA512)
            .build();
      default:
        throw new IllegalArgumentException("unsupported EC key type: " + pemKeyType);
    }
  }

  @AccessesPartialKey
  private static Key convertEcdsaPublicKey(PemKeyType pemKeyType, X509EncodedKeySpec keySpec)
      throws GeneralSecurityException {
    ECPublicKey key = parseEcPublicKey(keySpec, pemKeyType.keySizeInBits);
    return EcdsaPublicKey.builder()
          .setParameters(getEcdsaParameters(pemKeyType))
          .setPublicPoint(key.getW())
          .build();
  }

  // RFC 8410 defines the Ed25519 x509 public key encoding. This encoding always has the same
  // preamble, followed by the raw public key value.
  private static final byte[] x509PreambleEd25519 = Hex.decode("302a300506032b6570032100");

  @Nullable
  @AccessesPartialKey
  private static Key convertEd25519PublicKey(X509EncodedKeySpec keySpec)
      throws GeneralSecurityException {
    byte[] encodedKey = keySpec.getEncoded();
    if (!Util.isPrefix(x509PreambleEd25519, encodedKey)) {
      return null;
    }
    byte[] keyValue = Arrays.copyOfRange(encodedKey, x509PreambleEd25519.length, encodedKey.length);
    if (keyValue.length != 32) {
      return null;
    }
    return Ed25519PublicKey.create(Bytes.copyFrom(keyValue));
  }

  private static final MlDsaParameters ML_DSA_65_PARAMS =
      MlDsaParameters.create(
          MlDsaParameters.MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX);

  // RFC 9881 defines the ML-DSA-65 x509 public key encoding. This encoding always has the same
  // preamble, followed by the raw public key value.
  private static final byte[] x509PreambleMlDsa65 =
      Hex.decode("308207b2300b0609608648016503040312038207a100");

  @Nullable
  @AccessesPartialKey
  static MlDsaPublicKey convertMlDsa65PublicKey(X509EncodedKeySpec keySpec)
      throws GeneralSecurityException {
    byte[] encodedKey = keySpec.getEncoded();
    if (!Util.isPrefix(x509PreambleMlDsa65, encodedKey)) {
      throw new GeneralSecurityException("is not a ML-DSA-65 public key");
    }
    byte[] keyValue = Arrays.copyOfRange(encodedKey, x509PreambleMlDsa65.length, encodedKey.length);
    if (keyValue.length != 1952) {
      throw new GeneralSecurityException("wrong key length");
    }
    return MlDsaPublicKey.builder()
        .setParameters(ML_DSA_65_PARAMS)
        .setSerializedPublicKey(Bytes.copyFrom(keyValue))
        .build();
  }
}
