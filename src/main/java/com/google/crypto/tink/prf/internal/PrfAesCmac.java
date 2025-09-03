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

package com.google.crypto.tink.prf.internal;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.mac.internal.AesUtil;
import com.google.crypto.tink.prf.AesCmacPrfKey;
import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.Validators;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * An implementation of CMAC following <a href="https://tools.ietf.org/html/rfc4493">RFC 4493</a>.
 */
@Immutable
@AccessesPartialKey
public final class PrfAesCmac implements Prf {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  @SuppressWarnings("Immutable")
  private final SecretKey keySpec;

  @SuppressWarnings("Immutable")
  private byte[] subKey1;

  @SuppressWarnings("Immutable")
  private byte[] subKey2;

  private static final ThreadLocal<Cipher> localAesCipher =
      new ThreadLocal<Cipher>() {
        @Override
        protected Cipher initialValue() {
          try {
            return EngineFactory.CIPHER.getInstance("AES/ECB/NoPadding");
          } catch (GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
          }
        }
      };

  private static Cipher instance() throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException("Can not use AES-CMAC in FIPS-mode.");
    }
    return localAesCipher.get();
  }

  private PrfAesCmac(final byte[] key) throws GeneralSecurityException {
    Validators.validateAesKeySize(key.length);

    keySpec = new SecretKeySpec(key, "AES");
    generateSubKeys();
  }

  public static Prf create(AesCmacPrfKey key) throws GeneralSecurityException {
    return new PrfAesCmac(key.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get()));
  }

  // Only visible for testing.
  static int calcN(int dataLength) {
    if (dataLength == 0) {
      return 1;
    }
    return (dataLength - 1) / AesUtil.BLOCK_SIZE + 1;
  }

  private static void xorBlock(final byte[] x, final byte[] y, int offsetY, byte[] output) {
    for (int i = 0; i < AesUtil.BLOCK_SIZE; i++) {
      output[i] = (byte) (x[i] ^ y[i + offsetY]);
    }
  }

  // https://tools.ietf.org/html/rfc4493#section-2.4
  @Override
  public byte[] compute(final byte[] data, int outputLength) throws GeneralSecurityException {
    if (outputLength > AesUtil.BLOCK_SIZE) {
      throw new InvalidAlgorithmParameterException(
          "outputLength too large, max is " + AesUtil.BLOCK_SIZE + " bytes");
    }
    Cipher aes = instance();
    aes.init(Cipher.ENCRYPT_MODE, keySpec);

    // n is the number of blocks (including partial blocks) into which the data
    // is divided. Empty data is divided into 1 empty block.
    // Step 2: n = ceil(length / blocksize)
    int n = calcN(data.length);

    // Step 3
    boolean flag = (n * AesUtil.BLOCK_SIZE == data.length);

    // Step 4
    byte[] mLast;
    if (flag) {
      mLast = Bytes.xor(data, (n - 1) * AesUtil.BLOCK_SIZE, subKey1, 0, AesUtil.BLOCK_SIZE);
    } else {
      mLast =
          Bytes.xor(
              AesUtil.cmacPad(Arrays.copyOfRange(data, (n - 1) * AesUtil.BLOCK_SIZE, data.length)),
              subKey2);
    }

    // Step 5
    byte[] x = new byte[AesUtil.BLOCK_SIZE];

    // Step 6
    byte[] y = new byte[AesUtil.BLOCK_SIZE];
    for (int i = 0; i < n - 1; i++) {
      xorBlock(x, data, i * AesUtil.BLOCK_SIZE, /* output= */ y);
      int written = aes.doFinal(y, 0, AesUtil.BLOCK_SIZE, /* output= */ x);
      if (written != AesUtil.BLOCK_SIZE) {
        throw new IllegalStateException("Cipher didn't write full block");
      }
    }
    xorBlock(x, mLast, 0, /* output= */ y);

    // Step 7
    int written = aes.doFinal(y, 0, AesUtil.BLOCK_SIZE, /* output= */ x);
    if (written != AesUtil.BLOCK_SIZE) {
      throw new IllegalStateException("Cipher didn't write full block");
    }
    if (x.length == outputLength) {
      return x;
    }
    return Arrays.copyOf(x, outputLength);
  }

  // https://tools.ietf.org/html/rfc4493#section-2.3
  private void generateSubKeys() throws GeneralSecurityException {
    Cipher aes = instance();
    aes.init(Cipher.ENCRYPT_MODE, keySpec);
    byte[] zeroes = new byte[AesUtil.BLOCK_SIZE];
    byte[] l = aes.doFinal(zeroes);
    subKey1 = AesUtil.dbl(l);
    subKey2 = AesUtil.dbl(subKey1);
  }
}
