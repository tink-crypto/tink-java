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
import com.google.crypto.tink.internal.ProtoBasedConfigurationBuilder;
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
    return new ProtoBasedConfigurationBuilder()
        .addPrimitiveWrapper(Aead.class, Aead.class, WrappedAead::create)
        .addPrimitiveWrapper(Mac.class, Mac.class, WrappedMac::create)
        .addPrimitiveWrapper(ChunkedMac.class, ChunkedMac.class, WrappedChunkedMac::create)
        .addPrimitiveWrapper(PrfSet.class, Prf.class, WrappedPrfSet::create)
        .addPrimitiveWrapper(
            PublicKeySign.class, PublicKeySign.class, WrappedPublicKeySign::create)
        .addPrimitiveWrapper(
            PublicKeyVerify.class, PublicKeyVerify.class, WrappedPublicKeyVerify::create)
        // AEAD
        .addPrimitiveConstructor(
            EncryptThenAuthenticate::create, AesCtrHmacAeadKey.class, Aead.class)
        .addPrimitiveConstructor(AesGcmJce::create, AesGcmKey.class, Aead.class)
        // Mac
        .addPrimitiveConstructor(PrfMac::create, HmacKey.class, Mac.class)
        .addPrimitiveConstructor(ChunkedHmacImpl::new, HmacKey.class, ChunkedMac.class)
        // PRF
        .addPrimitiveConstructor(PrfHmacJce::create, HmacPrfKey.class, Prf.class)
        // PublicKeySign
        .addPrimitiveConstructor(
            EcdsaSignJce::create, EcdsaPrivateKey.class, PublicKeySign.class)
        .addPrimitiveConstructor(
            ConfigurationFips140v2::rsaSsaPkcs1SignCreate,
            RsaSsaPkcs1PrivateKey.class,
            PublicKeySign.class)
        .addPrimitiveConstructor(
            ConfigurationFips140v2::rsaSsaPssSignCreate,
            RsaSsaPssPrivateKey.class,
            PublicKeySign.class)
        // PublicKeyVerify
        .addPrimitiveConstructor(
            EcdsaVerifyJce::create, EcdsaPublicKey.class, PublicKeyVerify.class)
        .addPrimitiveConstructor(
            ConfigurationFips140v2::rsaSsaPkcs1VerifyCreate,
            RsaSsaPkcs1PublicKey.class,
            PublicKeyVerify.class)
        .addPrimitiveConstructor(
            ConfigurationFips140v2::rsaSsaPssVerifyCreate,
            RsaSsaPssPublicKey.class,
            PublicKeyVerify.class)
        .build();
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
