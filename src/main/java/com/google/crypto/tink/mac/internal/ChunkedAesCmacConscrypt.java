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

package com.google.crypto.tink.mac.internal;

import static com.google.crypto.tink.internal.Util.isPrefix;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.mac.AesCmacKey;
import com.google.crypto.tink.mac.AesCmacParameters;
import com.google.crypto.tink.mac.ChunkedMac;
import com.google.crypto.tink.mac.ChunkedMacComputation;
import com.google.crypto.tink.mac.ChunkedMacVerification;
import com.google.crypto.tink.subtle.Bytes;
import com.google.errorprone.annotations.Immutable;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** AES-CMAC implementation of {@link ChunkedMac}, using Conscrypt's native implementation. */
@Immutable
public final class ChunkedAesCmacConscrypt implements ChunkedMac {
  // The algorithm AES-CMAC is FIPS-compliant, but Conscrypt's implementation is not yet validated.
  private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  @SuppressWarnings("Immutable") // We never change outputPrefix.
  private final byte[] outputPrefix;

  private final AesCmacParameters parameters;

  @SuppressWarnings("Immutable") // We never change secretKeySpec.
  private final SecretKeySpec secretKeySpec;

  @SuppressWarnings("Immutable") // We never change the provider.
  private final Provider conscrypt;

  @AccessesPartialKey
  private static SecretKeySpec toSecretKeySpec(AesCmacKey key) {
    return new SecretKeySpec(key.getAesKey().toByteArray(InsecureSecretKeyAccess.get()), "AES");
  }

  private ChunkedAesCmacConscrypt(AesCmacKey key, Provider conscrypt)
      throws GeneralSecurityException {
    if (conscrypt == null) {
      throw new IllegalArgumentException("conscrypt is null");
    }
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException("Cannot use AES-CMAC in FIPS-mode.");
    }
    try {
      Mac unused = Mac.getInstance("AESCMAC", conscrypt);
    } catch (NoSuchAlgorithmException e) {
      throw new GeneralSecurityException("AES-CMAC not available.", e);
    }
    this.conscrypt = conscrypt;
    this.outputPrefix = key.getOutputPrefix().toByteArray();
    this.parameters = key.getParameters();
    this.secretKeySpec = toSecretKeySpec(key);
  }

  private static final class AesCmacComputation implements ChunkedMacComputation {
    // A single byte to be added to the plaintext for the legacy key type.
    private static final byte[] legacyFormatVersion = new byte[] {0};

    private final byte[] outputPrefix;
    private final AesCmacParameters parameters;
    private final Mac aesCmac;
    private boolean finalized = false;

    private AesCmacComputation(
        SecretKeySpec secretKeySpec,
        AesCmacParameters parameters,
        byte[] outputPrefix,
        Provider conscrypt)
        throws GeneralSecurityException {
      this.parameters = parameters;
      this.outputPrefix = outputPrefix;
      aesCmac = Mac.getInstance("AESCMAC", conscrypt);
      aesCmac.init(secretKeySpec);
    }

    @Override
    public void update(ByteBuffer data) {
      if (finalized) {
        throw new IllegalStateException(
            "Cannot update after computing the MAC tag. Please create a new object.");
      }
      aesCmac.update(data);
    }

    @Override
    public byte[] computeMac() throws GeneralSecurityException {
      if (finalized) {
        throw new IllegalStateException(
            "Cannot compute after computing the MAC tag. Please create a new object.");
      }
      finalized = true;
      if (parameters.getVariant() == AesCmacParameters.Variant.LEGACY) {
        aesCmac.update(legacyFormatVersion);
      }
      return Bytes.concat(
          outputPrefix,
          Arrays.copyOf(aesCmac.doFinal(), parameters.getCryptographicTagSizeBytes()));
    }
  }

  @Override
  public ChunkedMacComputation createComputation() throws GeneralSecurityException {
    return new AesCmacComputation(secretKeySpec, parameters, outputPrefix, conscrypt);
  }

  @Override
  public ChunkedMacVerification createVerification(final byte[] tag)
      throws GeneralSecurityException {
    if (!isPrefix(outputPrefix, tag)) {
      throw new GeneralSecurityException("Wrong tag prefix");
    }
    return ChunkedMacVerificationFromComputation.create(createComputation(), tag);
  }

  public static ChunkedMac create(AesCmacKey key, Provider conscrypt)
      throws GeneralSecurityException {
    return new ChunkedAesCmacConscrypt(key, conscrypt);
  }
}
