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
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.Ed25519Parameters;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import com.google.crypto.tink.signature.Ed25519PublicKey;
import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/** Creates Ed25519 keys. */
public final class Ed25519KeyCreator {

  @AccessesPartialKey
  public static Ed25519PrivateKey createKey(
      Ed25519Parameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot create a new Ed25519 Key as FIPS mode is enabled.");
    }
    Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPair();
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.create(
            parameters.getVariant(), Bytes.copyFrom(keyPair.getPublicKey()), idRequirement);
    return Ed25519PrivateKey.create(
        publicKey, SecretBytes.copyFrom(keyPair.getPrivateKey(), InsecureSecretKeyAccess.get()));
  }

  private Ed25519KeyCreator() {}
}
