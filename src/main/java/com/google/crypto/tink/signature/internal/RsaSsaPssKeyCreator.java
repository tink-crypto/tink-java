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

package com.google.crypto.tink.signature.internal;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssPublicKey;
import com.google.crypto.tink.util.SecretBigInteger;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import javax.annotation.Nullable;

/** Creates RSA-SSA-PSS keys. */
public final class RsaSsaPssKeyCreator {

  @AccessesPartialKey
  public static RsaSsaPssPrivateKey createKey(
      RsaSsaPssParameters parameters,
      @Nullable Integer idRequirement,
      @Nullable Provider provider)
      throws GeneralSecurityException {
    KeyPairGenerator keyGen =
        provider == null
            ? KeyPairGenerator.getInstance("RSA")
            : KeyPairGenerator.getInstance("RSA", provider);
    RSAKeyGenParameterSpec spec =
        new RSAKeyGenParameterSpec(
            parameters.getModulusSizeBits(),
            new BigInteger(1, parameters.getPublicExponent().toByteArray()));
    keyGen.initialize(spec);
    KeyPair keyPair = keyGen.generateKeyPair();
    RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();

    // Creates RsaSsaPssPublicKey.
    RsaSsaPssPublicKey rsaSsaPssPublicKey =
        RsaSsaPssPublicKey.builder()
            .setParameters(parameters)
            .setModulus(pubKey.getModulus())
            .setIdRequirement(idRequirement)
            .build();

    // Creates RsaSsaPssPrivateKey.
    return RsaSsaPssPrivateKey.builder()
        .setPublicKey(rsaSsaPssPublicKey)
        .setPrimes(
            SecretBigInteger.fromBigInteger(privKey.getPrimeP(), InsecureSecretKeyAccess.get()),
            SecretBigInteger.fromBigInteger(privKey.getPrimeQ(), InsecureSecretKeyAccess.get()))
        .setPrivateExponent(
            SecretBigInteger.fromBigInteger(
                privKey.getPrivateExponent(), InsecureSecretKeyAccess.get()))
        .setPrimeExponents(
            SecretBigInteger.fromBigInteger(
                privKey.getPrimeExponentP(), InsecureSecretKeyAccess.get()),
            SecretBigInteger.fromBigInteger(
                privKey.getPrimeExponentQ(), InsecureSecretKeyAccess.get()))
        .setCrtCoefficient(
            SecretBigInteger.fromBigInteger(
                privKey.getCrtCoefficient(), InsecureSecretKeyAccess.get()))
        .build();
  }

  @AccessesPartialKey
  public static RsaSsaPssPrivateKey createKey(
      RsaSsaPssParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    return createKey(parameters, idRequirement, null);
  }

  private RsaSsaPssKeyCreator() {}
}
