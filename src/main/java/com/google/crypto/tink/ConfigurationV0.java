// Copyright 2024 Google LLC
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

package com.google.crypto.tink;

import com.google.crypto.tink.aead.AesCtrHmacAeadKey;
import com.google.crypto.tink.aead.AesEaxKey;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.AesGcmSivKey;
import com.google.crypto.tink.aead.ChaCha20Poly1305Key;
import com.google.crypto.tink.aead.XChaCha20Poly1305Key;
import com.google.crypto.tink.aead.internal.ChaCha20Poly1305Jce;
import com.google.crypto.tink.aead.internal.WrappedAead;
import com.google.crypto.tink.aead.internal.XChaCha20Poly1305Jce;
import com.google.crypto.tink.aead.subtle.AesGcmSiv;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.daead.AesSivKey;
import com.google.crypto.tink.daead.internal.WrappedDeterministicAead;
import com.google.crypto.tink.hybrid.EciesPrivateKey;
import com.google.crypto.tink.hybrid.EciesPublicKey;
import com.google.crypto.tink.hybrid.HpkePrivateKey;
import com.google.crypto.tink.hybrid.HpkePublicKey;
import com.google.crypto.tink.hybrid.internal.HpkeDecrypt;
import com.google.crypto.tink.hybrid.internal.HpkeEncrypt;
import com.google.crypto.tink.hybrid.internal.WrappedHybridDecrypt;
import com.google.crypto.tink.hybrid.internal.WrappedHybridEncrypt;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.mac.AesCmacKey;
import com.google.crypto.tink.mac.ChunkedMac;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.internal.ChunkedAesCmacImpl;
import com.google.crypto.tink.mac.internal.ChunkedHmacImpl;
import com.google.crypto.tink.mac.internal.WrappedChunkedMac;
import com.google.crypto.tink.mac.internal.WrappedMac;
import com.google.crypto.tink.prf.AesCmacPrfKey;
import com.google.crypto.tink.prf.HkdfPrfKey;
import com.google.crypto.tink.prf.HkdfPrfParameters;
import com.google.crypto.tink.prf.HmacPrfKey;
import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.prf.PrfSet;
import com.google.crypto.tink.prf.internal.WrappedPrfSet;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import com.google.crypto.tink.signature.Ed25519PublicKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssPublicKey;
import com.google.crypto.tink.signature.internal.WrappedPublicKeySign;
import com.google.crypto.tink.signature.internal.WrappedPublicKeyVerify;
import com.google.crypto.tink.streamingaead.AesCtrHmacStreamingKey;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.streamingaead.internal.WrappedStreamingAead;
import com.google.crypto.tink.subtle.AesCtrHmacStreaming;
import com.google.crypto.tink.subtle.AesEaxJce;
import com.google.crypto.tink.subtle.AesGcmHkdfStreaming;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.AesSiv;
import com.google.crypto.tink.subtle.ChaCha20Poly1305;
import com.google.crypto.tink.subtle.EcdsaSignJce;
import com.google.crypto.tink.subtle.EcdsaVerifyJce;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridDecrypt;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridEncrypt;
import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.subtle.Ed25519Verify;
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.crypto.tink.subtle.PrfAesCmac;
import com.google.crypto.tink.subtle.PrfHmacJce;
import com.google.crypto.tink.subtle.PrfMac;
import com.google.crypto.tink.subtle.RsaSsaPkcs1SignJce;
import com.google.crypto.tink.subtle.RsaSsaPkcs1VerifyJce;
import com.google.crypto.tink.subtle.RsaSsaPssSignJce;
import com.google.crypto.tink.subtle.RsaSsaPssVerifyJce;
import com.google.crypto.tink.subtle.XChaCha20Poly1305;
import com.google.crypto.tink.subtle.prf.HkdfStreamingPrf;
import com.google.crypto.tink.subtle.prf.PrfImpl;
import java.security.GeneralSecurityException;

/**
 * ConfigurationV0 contains the following primitives and algorithms:
 *
 * <p>MAC/ChunkedMAC:
 *
 * <ul>
 *   <li>AesCmac
 *   <li>Hmac
 * </ul>
 *
 * <p>AEAD:
 *
 * <ul>
 *   <li>AesCtrHmac
 *   <li>AesEax
 *   <li>AesGcm
 *   <li>AesGcmSiv
 *   <li>ChaCha20Poly1305
 *   <li>XChaCha20Poly1305
 * </ul>
 *
 * <p>DAEAD:
 *
 * <ul>
 *   <li>AesSiv
 * </ul>
 *
 * <p>StreamingAEAD:
 *
 * <ul>
 *   <li>AesCtrHmac
 *   <li>AesGcmHkdf
 * </ul>
 *
 * <p>Hybrid:
 *
 * <ul>
 *   <li>Ecies
 *   <li>Hpke
 * </ul>
 *
 * <p>PRF:
 *
 * <ul>
 *   <li>AesCmac
 *   <li>Hkdf
 *   <li>Hmac
 * </ul>
 *
 * <p>Signatures:
 *
 * <ul>
 *   <li>Ed25519
 *   <li>Ecdsa
 *   <li>RsaSsaPkcs1
 *   <li>RsaSsaPss
 * </ul>
 */
public class ConfigurationV0 {
  private ConfigurationV0() {}

  private static final Configuration CONFIGURATION = create();

  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant ConfigurationV0 in FIPS mode");
    }
    return CONFIGURATION;
  }

  private static Configuration create() {
    return new Configuration() {
      @Override
      public <P> P createPrimitive(KeysetHandleInterface keysetHandle, Class<P> clazz)
          throws GeneralSecurityException {
        if (clazz.equals(Mac.class)) {
          return clazz.cast(WrappedMac.create(keysetHandle, ConfigurationV0::createMac));
        }
        if (clazz.equals(ChunkedMac.class)) {
          return clazz.cast(
              WrappedChunkedMac.create(keysetHandle, ConfigurationV0::createChunkedMac));
        }
        if (clazz.equals(Aead.class)) {
          return clazz.cast(WrappedAead.create(keysetHandle, ConfigurationV0::createAead));
        }
        if (clazz.equals(DeterministicAead.class)) {
          return clazz.cast(
              WrappedDeterministicAead.create(
                  keysetHandle, ConfigurationV0::createDeterministicAead));
        }
        if (clazz.equals(StreamingAead.class)) {
          return clazz.cast(
              WrappedStreamingAead.wrap(keysetHandle, ConfigurationV0::createStreamingAead));
        }
        if (clazz.equals(HybridEncrypt.class)) {
          return clazz.cast(
              WrappedHybridEncrypt.create(keysetHandle, ConfigurationV0::createHybridEncrypt));
        }
        if (clazz.equals(HybridDecrypt.class)) {
          return clazz.cast(
              WrappedHybridDecrypt.create(keysetHandle, ConfigurationV0::createHybridDecrypt));
        }
        if (clazz.equals(PrfSet.class)) {
          return clazz.cast(WrappedPrfSet.create(keysetHandle, ConfigurationV0::createPrf));
        }
        if (clazz.equals(PublicKeySign.class)) {
          return clazz.cast(
              WrappedPublicKeySign.create(keysetHandle, ConfigurationV0::createPublicKeySign));
        }
        if (clazz.equals(PublicKeyVerify.class)) {
          return clazz.cast(
              WrappedPublicKeyVerify.create(keysetHandle, ConfigurationV0::createPublicKeyVerify));
        }
        throw new GeneralSecurityException(
            "ConfigurationV0 does not support creating primitives of type " + clazz.getName());
      }
    };
  }

  // For compatibility reasons, and on some versions of Android for correctness reasons,
  // we do not remove our implementation of ChaCha20Poly1305, and fall back to it in cases
  // where we cannot use the JCE implementation.
  private static Aead createChaCha20Poly1305(ChaCha20Poly1305Key key)
      throws GeneralSecurityException {
    if (ChaCha20Poly1305Jce.isSupported()) {
      return ChaCha20Poly1305Jce.create(key);
    }
    return ChaCha20Poly1305.create(key);
  }

  // For compatibility reasons, and on some versions of Android for correctness reasons,
  // we do not remove our implementation of XChaCha20Poly1305, and fall back to it in cases
  // where we cannot use the JCE implementation.
  private static Aead createXChaCha20Poly1305(XChaCha20Poly1305Key key)
      throws GeneralSecurityException {
    if (XChaCha20Poly1305Jce.isSupported()) {
      return XChaCha20Poly1305Jce.create(key);
    }
    return XChaCha20Poly1305.create(key);
  }

  private static DeterministicAead createAesSiv(AesSivKey key) throws GeneralSecurityException {
    int aesSivKeySizeInBytes = 64;
    if (key.getParameters().getKeySizeBytes() != aesSivKeySizeInBytes) {
      throw new GeneralSecurityException(
          "invalid key size: "
              + key.getParameters().getKeySizeBytes()
              + ". Valid keys must have "
              + aesSivKeySizeInBytes
              + " bytes.");
    }
    return AesSiv.create(key);
  }

  private static Prf createHkdfPrf(HkdfPrfKey key) throws GeneralSecurityException {
    // We use a somewhat larger minimum key size than usual, because PRFs might be used by many
    // users,
    // in which case the security can degrade by a factor depending on the number of users.
    // (Discussed
    // for example in https://eprint.iacr.org/2012/159)
    int minHkdfPrfKeySize = 32;
    if (key.getParameters().getKeySizeBytes() < minHkdfPrfKeySize) {
      throw new GeneralSecurityException("Key size must be at least " + minHkdfPrfKeySize);
    }
    if (key.getParameters().getHashType() != HkdfPrfParameters.HashType.SHA256
        && key.getParameters().getHashType() != HkdfPrfParameters.HashType.SHA512) {
      throw new GeneralSecurityException("Hash type must be SHA256 or SHA512");
    }
    return PrfImpl.wrap(HkdfStreamingPrf.create(key));
  }

  // We only allow 32-byte AesCmac keys.
  private static final int AES_CMAC_KEY_SIZE_BYTES = 32;

  private static Prf createAesCmacPrf(AesCmacPrfKey key) throws GeneralSecurityException {
    if (key.getParameters().getKeySizeBytes() != AES_CMAC_KEY_SIZE_BYTES) {
      throw new GeneralSecurityException("Key size must be 32 bytes");
    }
    return PrfAesCmac.create(key);
  }

  private static ChunkedMac createChunkedAesCmac(AesCmacKey key) throws GeneralSecurityException {
    if (key.getParameters().getKeySizeBytes() != AES_CMAC_KEY_SIZE_BYTES) {
      throw new GeneralSecurityException("AesCmac key size is not 32 bytes");
    }
    return ChunkedAesCmacImpl.create(key);
  }

  private static Mac createAesCmac(AesCmacKey key) throws GeneralSecurityException {
    if (key.getParameters().getKeySizeBytes() != AES_CMAC_KEY_SIZE_BYTES) {
      throw new GeneralSecurityException("AesCmac key size is not 32 bytes");
    }
    return PrfMac.create(key);
  }

  private static Key reparseLegacyProtoKey(Key key) throws GeneralSecurityException {
    if (key instanceof LegacyProtoKey) {
      return MutableSerializationRegistry.globalInstance()
          .parseKey(
              ((LegacyProtoKey) key).getSerialization(InsecureSecretKeyAccess.get()),
              InsecureSecretKeyAccess.get());
    }
    return key;
  }

  private static Mac createMac(KeysetHandleInterface.Entry entry) throws GeneralSecurityException {
    Key key = reparseLegacyProtoKey(entry.getKey());

    if (key instanceof AesCmacKey) {
      return createAesCmac((AesCmacKey) key);
    }
    if (key instanceof HmacKey) {
      return PrfMac.create((HmacKey) key);
    }
    throw new GeneralSecurityException("Cannot create Mac for key " + key);
  }

  private static ChunkedMac createChunkedMac(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = reparseLegacyProtoKey(entry.getKey());
    if (key instanceof AesCmacKey) {
      return createChunkedAesCmac((AesCmacKey) key);
    }
    if (key instanceof HmacKey) {
      return new ChunkedHmacImpl((HmacKey) key);
    }
    throw new GeneralSecurityException("Cannot create ChunkedMac for key " + key);
  }

  private static Aead createAead(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = reparseLegacyProtoKey(entry.getKey());

    if (key instanceof AesCtrHmacAeadKey) {
      return EncryptThenAuthenticate.create((AesCtrHmacAeadKey) key);
    }
    if (key instanceof AesEaxKey) {
      return AesEaxJce.create((AesEaxKey) key);
    }
    if (key instanceof AesGcmKey) {
      return AesGcmJce.create((AesGcmKey) key);
    }
    if (key instanceof AesGcmSivKey) {
      return AesGcmSiv.create((AesGcmSivKey) key);
    }
    if (key instanceof ChaCha20Poly1305Key) {
      return createChaCha20Poly1305((ChaCha20Poly1305Key) key);
    }
    if (key instanceof XChaCha20Poly1305Key) {
      return createXChaCha20Poly1305((XChaCha20Poly1305Key) key);
    }
    throw new GeneralSecurityException("Cannot create Aead for key " + key);
  }

  private static DeterministicAead createDeterministicAead(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = reparseLegacyProtoKey(entry.getKey());

    if (key instanceof AesSivKey) {
      return createAesSiv((AesSivKey) key);
    }
    throw new GeneralSecurityException("Cannot create DeterministicAead for key " + key);
  }

  private static StreamingAead createStreamingAead(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = reparseLegacyProtoKey(entry.getKey());

    if (key instanceof AesCtrHmacStreamingKey) {
      return AesCtrHmacStreaming.create((AesCtrHmacStreamingKey) key);
    }
    if (key instanceof AesGcmHkdfStreamingKey) {
      return AesGcmHkdfStreaming.create((AesGcmHkdfStreamingKey) key);
    }
    throw new GeneralSecurityException("Cannot create StreamingAead for key " + key);
  }

  private static HybridEncrypt createHybridEncrypt(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = reparseLegacyProtoKey(entry.getKey());

    if (key instanceof EciesPublicKey) {
      return EciesAeadHkdfHybridEncrypt.create((EciesPublicKey) key);
    }
    if (key instanceof HpkePublicKey) {
      return HpkeEncrypt.create((HpkePublicKey) key);
    }
    throw new GeneralSecurityException("Cannot create HybridEncrypt for key " + key);
  }

  private static HybridDecrypt createHybridDecrypt(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = reparseLegacyProtoKey(entry.getKey());

    if (key instanceof EciesPrivateKey) {
      return EciesAeadHkdfHybridDecrypt.create((EciesPrivateKey) key);
    }
    if (key instanceof HpkePrivateKey) {
      return HpkeDecrypt.create((HpkePrivateKey) key);
    }
    throw new GeneralSecurityException("Cannot create HybridDecrypt for key " + key);
  }

  private static Prf createPrf(KeysetHandleInterface.Entry entry) throws GeneralSecurityException {
    Key key = reparseLegacyProtoKey(entry.getKey());

    if (key instanceof AesCmacPrfKey) {
      return createAesCmacPrf((AesCmacPrfKey) key);
    }
    if (key instanceof HkdfPrfKey) {
      return createHkdfPrf((HkdfPrfKey) key);
    }
    if (key instanceof HmacPrfKey) {
      return PrfHmacJce.create((HmacPrfKey) key);
    }
    throw new GeneralSecurityException("Cannot create Prf for key " + key);
  }

  private static PublicKeySign createPublicKeySign(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = reparseLegacyProtoKey(entry.getKey());
    if (key instanceof EcdsaPrivateKey) {
      return EcdsaSignJce.create((EcdsaPrivateKey) key);
    }
    if (key instanceof Ed25519PrivateKey) {
      return Ed25519Sign.create((Ed25519PrivateKey) key);
    }
    if (key instanceof RsaSsaPkcs1PrivateKey) {
      return RsaSsaPkcs1SignJce.create((RsaSsaPkcs1PrivateKey) key);
    }
    if (key instanceof RsaSsaPssPrivateKey) {
      return RsaSsaPssSignJce.create((RsaSsaPssPrivateKey) key);
    }
    throw new GeneralSecurityException("Cannot create PublicKeySign for key " + key);
  }

  private static PublicKeyVerify createPublicKeyVerify(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = reparseLegacyProtoKey(entry.getKey());
    if (key instanceof EcdsaPublicKey) {
      return EcdsaVerifyJce.create((EcdsaPublicKey) key);
    }
    if (key instanceof Ed25519PublicKey) {
      return Ed25519Verify.create((Ed25519PublicKey) key);
    }
    if (key instanceof RsaSsaPkcs1PublicKey) {
      return RsaSsaPkcs1VerifyJce.create((RsaSsaPkcs1PublicKey) key);
    }
    if (key instanceof RsaSsaPssPublicKey) {
      return RsaSsaPssVerifyJce.create((RsaSsaPssPublicKey) key);
    }
    throw new GeneralSecurityException("Cannot create PublicKeyVerify for key " + key);
  }
}
