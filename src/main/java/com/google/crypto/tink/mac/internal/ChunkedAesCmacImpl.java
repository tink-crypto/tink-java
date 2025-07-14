// Copyright 2022 Google LLC
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

import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.mac.AesCmacKey;
import com.google.crypto.tink.mac.ChunkedMac;
import com.google.crypto.tink.mac.ChunkedMacComputation;
import com.google.crypto.tink.mac.ChunkedMacVerification;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.Provider;

/** AES-CMAC implementation of the ChunkedMac interface. */
@Immutable
public final class ChunkedAesCmacImpl implements ChunkedMac {
  private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  @SuppressWarnings("Immutable") // We never change the key.
  private final AesCmacKey key;

  // Visible for testing.
  public ChunkedAesCmacImpl(AesCmacKey key) {
    this.key = key;
  }

  @Override
  public ChunkedMacComputation createComputation() throws GeneralSecurityException {
    return new ChunkedAesCmacComputation(key);
  }

  @Override
  public ChunkedMacVerification createVerification(final byte[] tag)
      throws GeneralSecurityException {
    if (tag.length < key.getOutputPrefix().size()) {
      throw new GeneralSecurityException("Tag too short");
    }
    if (!key.getOutputPrefix().equals(Bytes.copyFrom(tag, 0, key.getOutputPrefix().size()))) {
      throw new GeneralSecurityException("Wrong tag prefix");
    }
    return ChunkedMacVerificationFromComputation.create(new ChunkedAesCmacComputation(key), tag);
  }

  /** Creates a {@link ChunkedMac} implementation for AES-CMAC. */
  public static ChunkedMac create(AesCmacKey key) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException("Cannot use AES-CMAC in FIPS-mode.");
    }
    Provider conscrypt = ConscryptUtil.providerOrNull();
    if (conscrypt != null) {
      try {
        // If available, we prefer to use Conscrypt's implementation of AES-CMAC.
        return ChunkedAesCmacConscrypt.create(key, conscrypt);
      } catch (GeneralSecurityException e) {
        // Fall back to the default implementation.
      }
    }
    return new ChunkedAesCmacImpl(key);
  }
}
