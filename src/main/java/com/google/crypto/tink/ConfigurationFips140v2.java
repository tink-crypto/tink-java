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
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.internal.WrappedAead;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.Random;
import com.google.crypto.tink.mac.ChunkedMac;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.internal.ChunkedHmacImpl;
import com.google.crypto.tink.mac.internal.WrappedChunkedMac;
import com.google.crypto.tink.mac.internal.WrappedMac;
import com.google.crypto.tink.prf.HmacPrfKey;
import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.prf.PrfSet;
import com.google.crypto.tink.prf.internal.WrappedPrfSet;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssPublicKey;
import com.google.crypto.tink.signature.internal.RsaSsaPkcs1VerifyConscrypt;
import com.google.crypto.tink.signature.internal.RsaSsaPssSignConscrypt;
import com.google.crypto.tink.signature.internal.RsaSsaPssVerifyConscrypt;
import com.google.crypto.tink.signature.internal.WrappedPublicKeySign;
import com.google.crypto.tink.signature.internal.WrappedPublicKeyVerify;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.EcdsaSignJce;
import com.google.crypto.tink.subtle.EcdsaVerifyJce;
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.crypto.tink.subtle.PrfHmacJce;
import com.google.crypto.tink.subtle.PrfMac;
import com.google.crypto.tink.subtle.RsaSsaPkcs1SignJce;
import java.security.GeneralSecurityException;

/**
 * ConfigurationFips140v2 contains Tink primitives that are compliant with <a
 * href="https://csrc.nist.gov/pubs/fips/140-2/upd2/final">FIPS 140-2</a>.
 */
public class ConfigurationFips140v2 {

  private static final Configuration CONFIGURATION = create();

  /** get returns a Configuration containing primitives that are FIPS 140-2 compliant. */
  public static Configuration get() throws GeneralSecurityException {
    // First, check that we've got Conscrypt built with the BoringCrypto module.
    if (!TinkFipsUtil.fipsModuleAvailable()) {
      throw new GeneralSecurityException(
          "Conscrypt is not available or does not support checking for FIPS build.");
    }
    Random.validateUsesConscrypt();
    return CONFIGURATION;
  }

  private static Configuration create() {
    return new Configuration() {
      @Override
      public <P> P createPrimitive(KeysetHandleInterface keysetHandle, Class<P> clazz)
          throws GeneralSecurityException {
        if (clazz.equals(Aead.class)) {
          return clazz.cast(WrappedAead.create(keysetHandle, ConfigurationFips140v2::createAead));
        }
        if (clazz.equals(Mac.class)) {
          return clazz.cast(WrappedMac.create(keysetHandle, ConfigurationFips140v2::createMac));
        }
        if (clazz.equals(ChunkedMac.class)) {
          return clazz.cast(
              WrappedChunkedMac.create(keysetHandle, ConfigurationFips140v2::createChunkedMac));
        }
        if (clazz.equals(PrfSet.class)) {
          return clazz.cast(WrappedPrfSet.create(keysetHandle, ConfigurationFips140v2::createPrf));
        }
        if (clazz.equals(PublicKeySign.class)) {
          return clazz.cast(
              WrappedPublicKeySign.create(
                  keysetHandle, ConfigurationFips140v2::createPublicKeySign));
        }
        if (clazz.equals(PublicKeyVerify.class)) {
          return clazz.cast(
              WrappedPublicKeyVerify.create(
                  keysetHandle, ConfigurationFips140v2::createPublicKeyVerify));
        }
        throw new GeneralSecurityException(
            "No primitive creator for " + clazz.getName() + " available in ConfigurationFips140v2");
      }
    };
  }

  private static Aead createAead(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = entry.getKey();
    if (key instanceof AesCtrHmacAeadKey) {
      return EncryptThenAuthenticate.create((AesCtrHmacAeadKey) key);
    }
    if (key instanceof AesGcmKey) {
      return AesGcmJce.create((AesGcmKey) key);
    }
    throw new GeneralSecurityException("Key type" + key.getClass() + " not supported for AEAD");
  }

  private static Mac createMac(KeysetHandleInterface.Entry entry) throws GeneralSecurityException {
    Key key = entry.getKey();
    if (key instanceof HmacKey) {
      return PrfMac.create((HmacKey) key);
    }
    throw new GeneralSecurityException("Key type" + key.getClass() + " not supported for MAC");
  }

  private static ChunkedMac createChunkedMac(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = entry.getKey();
    if (key instanceof HmacKey) {
      return new ChunkedHmacImpl((HmacKey) key);
    }
    throw new GeneralSecurityException(
        "Key type" + key.getClass() + " not supported for ChunkedMac");
  }

  private static Prf createPrf(KeysetHandleInterface.Entry entry) throws GeneralSecurityException {
    Key key = entry.getKey();
    if (key instanceof HmacPrfKey) {
      return PrfHmacJce.create((HmacPrfKey) key);
    }
    throw new GeneralSecurityException("Key type" + key.getClass() + " not supported for Prf");
  }

  private static PublicKeySign createPublicKeySign(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = entry.getKey();
    if (key instanceof EcdsaPrivateKey) {
      return EcdsaSignJce.create((EcdsaPrivateKey) key);
    }
    if (key instanceof RsaSsaPkcs1PrivateKey) {
      return rsaSsaPkcs1SignCreate((RsaSsaPkcs1PrivateKey) key);
    }
    if (key instanceof RsaSsaPssPrivateKey) {
      return rsaSsaPssSignCreate((RsaSsaPssPrivateKey) key);
    }
    throw new GeneralSecurityException(
        "Key type" + key.getClass() + " not supported for PublicKeySign");
  }

  private static PublicKeyVerify createPublicKeyVerify(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    Key key = entry.getKey();
    if (key instanceof EcdsaPublicKey) {
      return EcdsaVerifyJce.create((EcdsaPublicKey) key);
    }
    if (key instanceof RsaSsaPkcs1PublicKey) {
      return rsaSsaPkcs1VerifyCreate((RsaSsaPkcs1PublicKey) key);
    }
    if (key instanceof RsaSsaPssPublicKey) {
      return rsaSsaPssVerifyCreate((RsaSsaPssPublicKey) key);
    }
    throw new GeneralSecurityException(
        "Key type" + key.getClass() + " not supported for PublicKeyVerify");
  }

  private ConfigurationFips140v2() {}

  // In FIPS only mode we additionally check if the modulus is 2048 or 3072, as this is the
  // only size which is covered by the FIPS validation and supported by Tink.
  // See
  // https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/3318
  private static PublicKeySign rsaSsaPkcs1SignCreate(RsaSsaPkcs1PrivateKey key)
      throws GeneralSecurityException {
    if (key.getParameters().getModulusSizeBits() != 2048
        && key.getParameters().getModulusSizeBits() != 3072) {
      throw new GeneralSecurityException(
          "Cannot create FIPS-compliant PublicKeySign: wrong RsaSsaPkcs1 key modulus size");
    }
    return RsaSsaPkcs1SignJce.create(key);
  }

  private static PublicKeyVerify rsaSsaPkcs1VerifyCreate(RsaSsaPkcs1PublicKey key)
      throws GeneralSecurityException {
    if (key.getParameters().getModulusSizeBits() != 2048
        && key.getParameters().getModulusSizeBits() != 3072) {
      throw new GeneralSecurityException(
          "Cannot create FIPS-compliant PublicKeyVerify: wrong RsaSsaPkcs1 key modulus size");
    }
    return RsaSsaPkcs1VerifyConscrypt.create(key);
  }

  private static PublicKeySign rsaSsaPssSignCreate(RsaSsaPssPrivateKey key)
      throws GeneralSecurityException {
    if (key.getParameters().getModulusSizeBits() != 2048
        && key.getParameters().getModulusSizeBits() != 3072) {
      throw new GeneralSecurityException(
          "Cannot create FIPS-compliant PublicKeySign: wrong RsaSsaPss key modulus size");
    }
    return RsaSsaPssSignConscrypt.create(key);
  }

  private static PublicKeyVerify rsaSsaPssVerifyCreate(RsaSsaPssPublicKey key)
      throws GeneralSecurityException {
    if (key.getParameters().getModulusSizeBits() != 2048
        && key.getParameters().getModulusSizeBits() != 3072) {
      throw new GeneralSecurityException(
          "Cannot create FIPS-compliant PublicKeyVerify: wrong RsaSsaPss key modulus size");
    }
    return RsaSsaPssVerifyConscrypt.create(key);
  }
}
