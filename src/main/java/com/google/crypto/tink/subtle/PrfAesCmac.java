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

package com.google.crypto.tink.subtle;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.prf.AesCmacPrfKey;
import com.google.crypto.tink.prf.AesCmacPrfParameters;
import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.prf.internal.PrfAesCmacConscrypt;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;

/**
 * An implementation of CMAC following <a href="https://tools.ietf.org/html/rfc4493">RFC 4493</a>.
 */
@Immutable
@AccessesPartialKey
public final class PrfAesCmac implements Prf {
  private final Prf prf;

  @AccessesPartialKey
  private static AesCmacPrfKey createAesCmacPrfKey(byte[] key) throws GeneralSecurityException {
    return
        AesCmacPrfKey.create(
            AesCmacPrfParameters.create(key.length),
            SecretBytes.copyFrom(key, InsecureSecretKeyAccess.get()));
  }

  private PrfAesCmac(AesCmacPrfKey key) throws GeneralSecurityException {
    this.prf = create(key);
  }

  /**
   * Prefer to use {@link #create} instead of this constructor.
   */
  public PrfAesCmac(final byte[] key) throws GeneralSecurityException {
    this(createAesCmacPrfKey(key));
  }

  /* Uses two different PRF implementations for small and large data.*/
  @Immutable
  private static class PrfImplementation implements Prf {
    final Prf small;
    final Prf large;

    private static final int SMALL_DATA_SIZE = 64;

    @Override
    public byte[] compute(final byte[] data, int outputLength) throws GeneralSecurityException {
      if (data.length <= SMALL_DATA_SIZE) {
        return small.compute(data, outputLength);
      }
      return large.compute(data, outputLength);
    }

    private PrfImplementation(Prf small, Prf large) {
      this.small = small;
      this.large = large;
    }
  }

  public static Prf create(AesCmacPrfKey key) throws GeneralSecurityException {
    Prf prf = com.google.crypto.tink.prf.internal.PrfAesCmac.create(key);
    try {
      Prf conscryptPrf = PrfAesCmacConscrypt.create(key);
      // PrfAesCmacConscrypt is currently slower for small data. And it requires a global lock.
      // So we prefer not to use it for small data. But for large data, it is 10x faster
      // than PrfAesCmac.
      return new PrfImplementation(prf, conscryptPrf);
    } catch (GeneralSecurityException e) {
      // Fall back to this implementation if Conscrypt is not available.
      return prf;
    }
  }

  @Override
  public byte[] compute(final byte[] data, int outputLength) throws GeneralSecurityException {
    return prf.compute(data, outputLength);
  }
}
