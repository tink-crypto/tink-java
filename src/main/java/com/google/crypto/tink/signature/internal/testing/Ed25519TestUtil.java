// Copyright 2023 Google LLC
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

package com.google.crypto.tink.signature.internal.testing;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.signature.Ed25519Parameters;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import com.google.crypto.tink.signature.Ed25519PublicKey;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;

/** Test utilities for Ed25519. Test vectors are generated by hand for this test. */
@AccessesPartialKey
public final class Ed25519TestUtil {
  private static final Bytes PUBLIC_KEY_MATERIAL =
      Bytes.copyFrom(
          Hex.decode("ea42941a6dc801484390b2955bc7376d172eeb72640a54e5b50c95efa2fc6ad8"));
  private static final SecretBytes PRIVATE_KEY_MATERIAL =
      SecretBytes.copyFrom(
          Hex.decode("9cac7d19aeecc563a3dff7bcae0fbbbc28087b986c49a3463077dd5281437e81"),
          InsecureSecretKeyAccess.get());

  public static SignatureTestVector createTestVector0() throws GeneralSecurityException {
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.create(Ed25519Parameters.Variant.NO_PREFIX, PUBLIC_KEY_MATERIAL, null);
    Ed25519PrivateKey privateKey = Ed25519PrivateKey.create(publicKey, PRIVATE_KEY_MATERIAL);
    return new SignatureTestVector(
        privateKey,
        Hex.decode(
            "3431985050f48157551262d591d0f1f25b9c6808fce4345066cb8216d48fcd9feafa4b24949a7f8c"
                + "abdc16a51030a19d7514c9685c221475bf3cfc363472ee0a"),
        Hex.decode("aa"));
  }

  public static SignatureTestVector createTestVector1() throws GeneralSecurityException {
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.create(Ed25519Parameters.Variant.TINK, PUBLIC_KEY_MATERIAL, 0x99887766);
    Ed25519PrivateKey privateKey = Ed25519PrivateKey.create(publicKey, PRIVATE_KEY_MATERIAL);
    return new SignatureTestVector(
        privateKey,
        Hex.decode(
            "0199887766"
                + "3431985050f48157551262d591d0f1f25b9c6808fce4345066cb8216d48fcd9feafa4b24949a7f8c"
                + "abdc16a51030a19d7514c9685c221475bf3cfc363472ee0a"),
        Hex.decode("aa"));
  }

  public static SignatureTestVector createTestVector2() throws GeneralSecurityException {
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.create(Ed25519Parameters.Variant.CRUNCHY, PUBLIC_KEY_MATERIAL, 0x99887766);
    Ed25519PrivateKey privateKey = Ed25519PrivateKey.create(publicKey, PRIVATE_KEY_MATERIAL);
    return new SignatureTestVector(
        privateKey,
        Hex.decode(
            "0099887766"
                + "3431985050f48157551262d591d0f1f25b9c6808fce4345066cb8216d48fcd9feafa4b24949a7f8c"
                + "abdc16a51030a19d7514c9685c221475bf3cfc363472ee0a"),
        Hex.decode("aa"));
  }

  public static SignatureTestVector createTestVector3() throws GeneralSecurityException {
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.create(Ed25519Parameters.Variant.LEGACY, PUBLIC_KEY_MATERIAL, 0x99887766);
    Ed25519PrivateKey privateKey = Ed25519PrivateKey.create(publicKey, PRIVATE_KEY_MATERIAL);
    return new SignatureTestVector(
        privateKey,
        Hex.decode(
            "0099887766"
                + "e828586415b1226c118617a2b56b923b6717e83c4d265fcb4e2cdf3cb902ce7b9b1ecd840"
                + "5cb4e6a8e248ef5478891b5b6f80f737df16594f88662595d8f140e"),
        Hex.decode("aa"));
  }

  public static SignatureTestVector[] createEd25519TestVectors() {
    return exceptionIsBug(
        () ->
            new SignatureTestVector[] {
              createTestVector0(), createTestVector1(), createTestVector2(), createTestVector3()
            });
  }

  private Ed25519TestUtil() {}
}