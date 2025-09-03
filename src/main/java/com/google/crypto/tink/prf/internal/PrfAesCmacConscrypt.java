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

package com.google.crypto.tink.prf.internal;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.mac.internal.AesUtil;
import com.google.crypto.tink.prf.AesCmacPrfKey;
import com.google.crypto.tink.prf.Prf;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Provider;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * {@link com.google.crypto.tink.prf.Prf} implementation of AES-CMAC using Conscrypt.
 *
 * <p>AES-CMAC is defined in <a href="https://tools.ietf.org/html/rfc4493">RFC 4493</a> and
 * standardized by NIST in <a
 * href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf">800-38B</a>.
 *
 * <p>This implementation here supports both 128-bit and 256-bit keys.
 */
@Immutable
@AccessesPartialKey
public final class PrfAesCmacConscrypt implements Prf {
  // The algorithm AES-CMAC is FIPS-compliant, but Conscrypt's implementation is not yet validated.
  private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  /**
   * Returns a {@link com.google.crypto.tink.prf.Prf} primitive from an {@link
   * com.google.crypto.tink.prf.AesCmacPrfKey}.
   */
  public static Prf create(AesCmacPrfKey key) throws GeneralSecurityException {
    Provider conscrypt = ConscryptUtil.providerOrNull();
    if (conscrypt == null) {
      throw new GeneralSecurityException("Conscrypt not available");
    }

    // Check that conscrypt supports AESCMAC.
    Mac unused = Mac.getInstance("AESCMAC", conscrypt);

    return new PrfAesCmacConscrypt(
        key.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get()), conscrypt);
  }

  @SuppressWarnings("Immutable") // We do not mutate the key.
  private final java.security.Key key;

  @SuppressWarnings("Immutable") // The Conscrypt provider is immutable.
  private final Provider conscrypt;

  private PrfAesCmacConscrypt(byte[] keyBytes, Provider conscrypt) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Cannot use AES-CMAC in FIPS-mode, as BoringCrypto module is not available");
    }
    this.key = new SecretKeySpec(keyBytes, "AES");
    this.conscrypt = conscrypt;
  }

  @Override
  public byte[] compute(byte[] data, int outputLength) throws GeneralSecurityException {
    if (outputLength > AesUtil.BLOCK_SIZE) {
      throw new InvalidAlgorithmParameterException(
          "outputLength must not be larger than " + AesUtil.BLOCK_SIZE);
    }
    Mac mac = Mac.getInstance("AESCMAC", conscrypt);
    mac.init(key);
    byte[] result = mac.doFinal(data);
    if (outputLength == result.length) {
      return result;
    }
    return Arrays.copyOf(result, outputLength);
  }
}
