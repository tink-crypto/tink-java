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

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssPublicKey;
import com.google.crypto.tink.signature.internal.RsaSsaPssSignConscrypt;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.errorprone.annotations.Immutable;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchProviderException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.Cipher;

/**
 * RsaSsaPss (i.e. RSA Signature Schemes with Appendix (SSA) with PSS encoding) signing with JCE.
 */
@Immutable
public final class RsaSsaPssSignJce implements PublicKeySign {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  private static final byte[] EMPTY = new byte[0];
  private static final byte[] LEGACY_MESSAGE_SUFFIX = new byte[] {0};

  /**
   * InternalImpl is an implementation of the RSA SSA PSS signature signing that only uses the JCE
   * for raw RSA operations. The rest of the algorithm is implemented in Java. This allows it to be
   * used on most Java platforms.
   */
  private static final class InternalImpl implements PublicKeySign {

    @SuppressWarnings("Immutable")
    private final RSAPrivateCrtKey privateKey;

    @SuppressWarnings("Immutable")
    private final RSAPublicKey publicKey;

    private final HashType sigHash;
    private final HashType mgf1Hash;
    private final int saltLength;

    @SuppressWarnings("Immutable")
    private final byte[] outputPrefix;

    @SuppressWarnings("Immutable")
    private final byte[] messageSuffix;

    private static final String RAW_RSA_ALGORITHM = "RSA/ECB/NOPADDING";

    private InternalImpl(
        final RSAPrivateCrtKey priv,
        HashType sigHash,
        HashType mgf1Hash,
        int saltLength,
        byte[] outputPrefix,
        byte[] messageSuffix)
        throws GeneralSecurityException {
      if (TinkFipsUtil.useOnlyFips()) {
        throw new GeneralSecurityException(
            "Can not use RSA PSS in FIPS-mode, as BoringCrypto module is not available.");
      }

      Validators.validateSignatureHash(sigHash);
      if (!sigHash.equals(mgf1Hash)) {
        throw new GeneralSecurityException("sigHash and mgf1Hash must be the same");
      }
      Validators.validateRsaModulusSize(priv.getModulus().bitLength());
      Validators.validateRsaPublicExponent(priv.getPublicExponent());
      this.privateKey = priv;
      KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("RSA");
      this.publicKey =
          (RSAPublicKey)
              kf.generatePublic(new RSAPublicKeySpec(priv.getModulus(), priv.getPublicExponent()));
      this.sigHash = sigHash;
      this.mgf1Hash = mgf1Hash;
      this.saltLength = saltLength;
      this.outputPrefix = outputPrefix;
      this.messageSuffix = messageSuffix;
    }

    private byte[] noPrefixSign(final byte[] data)
        throws GeneralSecurityException { // https://tools.ietf.org/html/rfc8017#section-8.1.1.
      int modBits = publicKey.getModulus().bitLength();

      byte[] em = emsaPssEncode(data, modBits - 1);
      return rsasp1(em);
    }

    @Override
    public byte[] sign(final byte[] data) throws GeneralSecurityException {
      byte[] signature = noPrefixSign(data);
      if (outputPrefix.length == 0) {
        return signature;
      } else {
        return Bytes.concat(outputPrefix, signature);
      }
    }

    private byte[] rsasp1(byte[] m) throws GeneralSecurityException {
      Cipher decryptCipher = EngineFactory.CIPHER.getInstance(RAW_RSA_ALGORITHM);
      decryptCipher.init(Cipher.DECRYPT_MODE, this.privateKey);
      byte[] c = decryptCipher.doFinal(m);
      // To make sure the private key operation is correct, we check the result with public key
      // operation.
      Cipher encryptCipher = EngineFactory.CIPHER.getInstance(RAW_RSA_ALGORITHM);
      encryptCipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
      byte[] m0 = encryptCipher.doFinal(c);
      if (!new BigInteger(1, m).equals(new BigInteger(1, m0))) {
        throw new IllegalStateException("Security bug: RSA signature computation error");
      }
      return c;
    }

    // https://tools.ietf.org/html/rfc8017#section-9.1.1.
    private byte[] emsaPssEncode(byte[] message, int emBits) throws GeneralSecurityException {
      // Step 1. Length checking.
      // This step is unnecessary because Java's byte[] only supports up to 2^31 -1 bytes while the
      // input limitation for the hash function is far larger (2^61 - 1 for SHA-1).

      // Step 2. Compute hash.
      Validators.validateSignatureHash(sigHash);
      MessageDigest digest =
          EngineFactory.MESSAGE_DIGEST.getInstance(SubtleUtil.toDigestAlgo(this.sigHash));
      // M = concat(message, messageSuffix)
      digest.update(message);
      if (messageSuffix.length != 0) {
        digest.update(messageSuffix);
      }
      byte[] mHash = digest.digest();

      // Step 3. Check emLen.
      int hLen = digest.getDigestLength();
      int emLen = (emBits - 1) / 8 + 1;
      if (emLen < hLen + this.saltLength + 2) {
        throw new GeneralSecurityException("encoding error");
      }

      // Step 4. Generate random salt.
      byte[] salt = Random.randBytes(this.saltLength);

      // Step 5. Compute M'.
      byte[] mPrime = new byte[8 + hLen + this.saltLength];
      System.arraycopy(mHash, 0, mPrime, 8, hLen);
      System.arraycopy(salt, 0, mPrime, 8 + hLen, salt.length);

      // Step 6. Compute H.
      byte[] h = digest.digest(mPrime);

      // Step 7, 8. Generate DB.
      byte[] db = new byte[emLen - hLen - 1];
      db[emLen - this.saltLength - hLen - 2] = (byte) 0x01;
      System.arraycopy(salt, 0, db, emLen - this.saltLength - hLen - 1, salt.length);

      // Step 9. Compute dbMask.
      byte[] dbMask = SubtleUtil.mgf1(h, emLen - hLen - 1, this.mgf1Hash);

      // Step 10. Compute maskedDb.
      byte[] maskedDb = new byte[emLen - hLen - 1];
      for (int i = 0; i < maskedDb.length; i++) {
        maskedDb[i] = (byte) (db[i] ^ dbMask[i]);
      }

      // Step 11. Set the leftmost 8 * emLen - emBits bits of the leftmost octet in maskedDB to
      // zero.
      for (int i = 0; i < (long) emLen * 8 - emBits; i++) {
        int bytePos = i / 8;
        int bitPos = 7 - i % 8;
        maskedDb[bytePos] = (byte) (maskedDb[bytePos] & ~(1 << bitPos));
      }

      // Step 12. Generate EM.
      byte[] em = new byte[maskedDb.length + hLen + 1];
      System.arraycopy(maskedDb, 0, em, 0, maskedDb.length);
      System.arraycopy(h, 0, em, maskedDb.length, h.length);
      em[maskedDb.length + hLen] = (byte) 0xbc;
      return em;
    }
  }

  @SuppressWarnings("Immutable")
  private final PublicKeySign sign;

  @AccessesPartialKey
  public static PublicKeySign create(RsaSsaPssPrivateKey key) throws GeneralSecurityException {
    try {
      return RsaSsaPssSignConscrypt.create(key);
    } catch (NoSuchProviderException e) {
      // Ignore, and fall back to the Java implementation.
    }
    KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("RSA");
    RSAPrivateCrtKey privateKey =
        (RSAPrivateCrtKey)
            kf.generatePrivate(
                new RSAPrivateCrtKeySpec(
                    key.getPublicKey().getModulus(),
                    key.getParameters().getPublicExponent(),
                    key.getPrivateExponent().getBigInteger(InsecureSecretKeyAccess.get()),
                    key.getPrimeP().getBigInteger(InsecureSecretKeyAccess.get()),
                    key.getPrimeQ().getBigInteger(InsecureSecretKeyAccess.get()),
                    key.getPrimeExponentP().getBigInteger(InsecureSecretKeyAccess.get()),
                    key.getPrimeExponentQ().getBigInteger(InsecureSecretKeyAccess.get()),
                    key.getCrtCoefficient().getBigInteger(InsecureSecretKeyAccess.get())));
    RsaSsaPssParameters params = key.getParameters();
    return new InternalImpl(
        privateKey,
        RsaSsaPssVerifyJce.HASH_TYPE_CONVERTER.toProtoEnum(params.getSigHashType()),
        RsaSsaPssVerifyJce.HASH_TYPE_CONVERTER.toProtoEnum(params.getMgf1HashType()),
        params.getSaltLengthBytes(),
        key.getOutputPrefix().toByteArray(),
        key.getParameters().getVariant().equals(RsaSsaPssParameters.Variant.LEGACY)
            ? LEGACY_MESSAGE_SUFFIX
            : EMPTY);
  }

  private static RsaSsaPssParameters.HashType getHashType(HashType hash)
      throws GeneralSecurityException {
    switch (hash) {
      case SHA256:
        return RsaSsaPssParameters.HashType.SHA256;
      case SHA384:
        return RsaSsaPssParameters.HashType.SHA384;
      case SHA512:
        return RsaSsaPssParameters.HashType.SHA512;
      default:
        throw new GeneralSecurityException("Unsupported hash: " + hash);
    }
  }

  @AccessesPartialKey
  private RsaSsaPssPrivateKey convertKey(
      final RSAPrivateCrtKey key, HashType sigHash, HashType mgf1Hash, int saltLength)
      throws GeneralSecurityException {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(key.getModulus().bitLength())
            .setPublicExponent(key.getPublicExponent())
            .setSigHashType(getHashType(sigHash))
            .setMgf1HashType(getHashType(mgf1Hash))
            .setSaltLengthBytes(saltLength)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .build();
    return RsaSsaPssPrivateKey.builder()
        .setPublicKey(
            RsaSsaPssPublicKey.builder()
                .setParameters(parameters)
                .setModulus(key.getModulus())
                .build())
        .setPrimes(
            SecretBigInteger.fromBigInteger(key.getPrimeP(), InsecureSecretKeyAccess.get()),
            SecretBigInteger.fromBigInteger(key.getPrimeQ(), InsecureSecretKeyAccess.get()))
        .setPrivateExponent(
            SecretBigInteger.fromBigInteger(
                key.getPrivateExponent(), InsecureSecretKeyAccess.get()))
        .setPrimeExponents(
            SecretBigInteger.fromBigInteger(key.getPrimeExponentP(), InsecureSecretKeyAccess.get()),
            SecretBigInteger.fromBigInteger(key.getPrimeExponentQ(), InsecureSecretKeyAccess.get()))
        .setCrtCoefficient(
            SecretBigInteger.fromBigInteger(key.getCrtCoefficient(), InsecureSecretKeyAccess.get()))
        .build();
  }

  public RsaSsaPssSignJce(
      final RSAPrivateCrtKey priv, HashType sigHash, HashType mgf1Hash, int saltLength)
      throws GeneralSecurityException {
    this.sign = create(convertKey(priv, sigHash, mgf1Hash, saltLength));
  }

  @Override
  public byte[] sign(final byte[] data) throws GeneralSecurityException {
    return sign.sign(data);
  }
}
