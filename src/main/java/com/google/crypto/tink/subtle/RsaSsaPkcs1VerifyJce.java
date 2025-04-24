// Copyright 2018 Google Inc.
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

package com.google.crypto.tink.subtle;

import static com.google.crypto.tink.internal.Util.isPrefix;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.EnumTypeProtoConverter;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.signature.internal.RsaSsaPkcs1VerifyConscrypt;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.errorprone.annotations.Immutable;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchProviderException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

/**
 * RsaSsaPkcs1 (i.e. RSA Signature Schemes with Appendix (SSA) using PKCS1-v1_5 encoding) verifying
 * with JCE.
 */
@Immutable
public final class RsaSsaPkcs1VerifyJce implements PublicKeyVerify {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  private static final byte[] EMPTY = new byte[0];
  private static final byte[] legacyMessageSuffix = new byte[] {0};

  // This converter is not used with a proto but rather with an ordinary enum type.
  static final EnumTypeProtoConverter<HashType, RsaSsaPkcs1Parameters.HashType>
      HASH_TYPE_CONVERTER =
          EnumTypeProtoConverter.<HashType, RsaSsaPkcs1Parameters.HashType>builder()
              .add(HashType.SHA256, RsaSsaPkcs1Parameters.HashType.SHA256)
              .add(HashType.SHA384, RsaSsaPkcs1Parameters.HashType.SHA384)
              .add(HashType.SHA512, RsaSsaPkcs1Parameters.HashType.SHA512)
              .build();

  /** InternalJavaImpl is a Java implementation of the RSA-PKCS1.5 signature scheme. */
  private static final class InternalJavaImpl implements PublicKeyVerify {

    // See definitions in https://tools.ietf.org/html/rfc3447#page-43
    private static final String ASN_PREFIX_SHA256 = "3031300d060960864801650304020105000420";
    private static final String ASN_PREFIX_SHA384 = "3041300d060960864801650304020205000430";
    private static final String ASN_PREFIX_SHA512 = "3051300d060960864801650304020305000440";

    @SuppressWarnings("Immutable")
    private final RSAPublicKey publicKey;

    private final HashType hash;

    @SuppressWarnings("Immutable")
    private final byte[] outputPrefix;

    @SuppressWarnings("Immutable")
    private final byte[] messageSuffix;

    private InternalJavaImpl(
        final RSAPublicKey pubKey, HashType hash, byte[] outputPrefix, byte[] messageSuffix)
        throws GeneralSecurityException {
      if (TinkFipsUtil.useOnlyFips()) {
        throw new GeneralSecurityException(
            "Conscrypt is not available, and we cannot use Java Implementation of RSA-PKCS1.5 in"
                + " FIPS-mode.");
      }

      Validators.validateSignatureHash(hash);
      Validators.validateRsaModulusSize(pubKey.getModulus().bitLength());
      Validators.validateRsaPublicExponent(pubKey.getPublicExponent());
      this.publicKey = pubKey;
      this.hash = hash;
      this.outputPrefix = outputPrefix;
      this.messageSuffix = messageSuffix;
    }

    private void noPrefixVerify(final byte[] signature, final byte[] data)
        throws GeneralSecurityException {
      // The algorithm is described at (https://tools.ietf.org/html/rfc8017#section-8.2). As
      // signature
      // verification is a public operation,  throwing different exception messages doesn't give
      // attacker any useful information.
      BigInteger e = publicKey.getPublicExponent();
      BigInteger n = publicKey.getModulus();
      int nLengthInBytes = (n.bitLength() + 7) / 8;

      // Step 1. Length checking.
      if (nLengthInBytes != signature.length) {
        throw new GeneralSecurityException("invalid signature's length");
      }

      // Step 2. RSA verification.
      BigInteger s = SubtleUtil.bytes2Integer(signature);
      if (s.compareTo(n) >= 0) {
        throw new GeneralSecurityException("signature out of range");
      }
      BigInteger m = s.modPow(e, n);
      byte[] em = SubtleUtil.integer2Bytes(m, nLengthInBytes);

      // Step 3. PKCS1 encoding.
      byte[] expectedEm = emsaPkcs1(data, nLengthInBytes, hash);

      // Step 4. Compare the results.
      if (!Bytes.equal(em, expectedEm)) {
        throw new GeneralSecurityException("invalid signature");
      }
    }

    // https://tools.ietf.org/html/rfc8017#section-9.2.
    private byte[] emsaPkcs1(byte[] m, int emLen, HashType hash) throws GeneralSecurityException {
      Validators.validateSignatureHash(hash);
      MessageDigest digest =
          EngineFactory.MESSAGE_DIGEST.getInstance(SubtleUtil.toDigestAlgo(this.hash));
      digest.update(m);
      if (messageSuffix.length != 0) {
        digest.update(messageSuffix);
      }
      byte[] h = digest.digest();
      byte[] asnPrefix = toAsnPrefix(hash);
      int tLen = asnPrefix.length + h.length;
      if (emLen < tLen + 11) {
        throw new GeneralSecurityException("intended encoded message length too short");
      }
      byte[] em = new byte[emLen];
      int offset = 0;
      em[offset++] = 0x00;
      em[offset++] = 0x01;
      for (int i = 0; i < emLen - tLen - 3; i++) {
        em[offset++] = (byte) 0xff;
      }
      em[offset++] = 0x00;
      System.arraycopy(asnPrefix, 0, em, offset, asnPrefix.length);
      System.arraycopy(h, 0, em, offset + asnPrefix.length, h.length);
      return em;
    }

    private byte[] toAsnPrefix(HashType hash) throws GeneralSecurityException {
      switch (hash) {
        case SHA256:
          return Hex.decode(ASN_PREFIX_SHA256);
        case SHA384:
          return Hex.decode(ASN_PREFIX_SHA384);
        case SHA512:
          return Hex.decode(ASN_PREFIX_SHA512);
        default:
          throw new GeneralSecurityException("Unsupported hash " + hash);
      }
    }

    @Override
    public void verify(final byte[] signature, final byte[] data) throws GeneralSecurityException {
      if (outputPrefix.length == 0) {
        noPrefixVerify(signature, data);
        return;
      }
      if (!isPrefix(outputPrefix, signature)) {
        throw new GeneralSecurityException("Invalid signature (output prefix mismatch)");
      }
      byte[] signatureNoPrefix =
          Arrays.copyOfRange(signature, outputPrefix.length, signature.length);
      noPrefixVerify(signatureNoPrefix, data);
    }
  }

  @SuppressWarnings("Immutable")
  private final PublicKeyVerify verify;

  @AccessesPartialKey
  public static PublicKeyVerify create(RsaSsaPkcs1PublicKey key) throws GeneralSecurityException {
    try {
      return RsaSsaPkcs1VerifyConscrypt.create(key);
    } catch (NoSuchProviderException e) {
      // Ignore, and fall back to the Java implementation.
    }
    KeyFactory keyFactory = EngineFactory.KEY_FACTORY.getInstance("RSA");
    RSAPublicKey publicKey =
        (RSAPublicKey)
            keyFactory.generatePublic(
                new RSAPublicKeySpec(key.getModulus(), key.getParameters().getPublicExponent()));

    return new InternalJavaImpl(
        publicKey,
        HASH_TYPE_CONVERTER.toProtoEnum(key.getParameters().getHashType()),
        key.getOutputPrefix().toByteArray(),
        key.getParameters().getVariant().equals(RsaSsaPkcs1Parameters.Variant.LEGACY)
            ? legacyMessageSuffix
            : EMPTY);
  }

  private static RsaSsaPkcs1Parameters.HashType getHashType(HashType hash)
      throws GeneralSecurityException {
    switch (hash) {
      case SHA256:
        return RsaSsaPkcs1Parameters.HashType.SHA256;
      case SHA384:
        return RsaSsaPkcs1Parameters.HashType.SHA384;
      case SHA512:
        return RsaSsaPkcs1Parameters.HashType.SHA512;
      default:
        throw new GeneralSecurityException("Unsupported hash: " + hash);
    }
  }

  @AccessesPartialKey
  private RsaSsaPkcs1PublicKey convertKey(final RSAPublicKey pubKey, HashType hash)
      throws GeneralSecurityException {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(pubKey.getModulus().bitLength())
            .setPublicExponent(pubKey.getPublicExponent())
            .setHashType(getHashType(hash))
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    return RsaSsaPkcs1PublicKey.builder()
        .setParameters(parameters)
        .setModulus(pubKey.getModulus())
        .build();
  }

  // Consider using RsaSsaPkcs1VerifyJce.create instead.
  public RsaSsaPkcs1VerifyJce(final RSAPublicKey pubKey, HashType hash)
      throws GeneralSecurityException {

    this.verify = create(convertKey(pubKey, hash));
  }

  @Override
  public void verify(final byte[] signature, final byte[] data) throws GeneralSecurityException {
    verify.verify(signature, data);
  }
}
