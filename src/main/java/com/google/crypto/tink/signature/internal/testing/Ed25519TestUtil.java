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

/**
 * Test utilities for Ed25519. Test vectors are from
 * https://datatracker.ietf.org/doc/html/rfc8032#section-7.1 - TEST 3.
 */
@AccessesPartialKey
public final class Ed25519TestUtil {
  private static final Bytes PUBLIC_KEY_MATERIAL =
      Bytes.copyFrom(
          Hex.decode("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"));
  private static final SecretBytes PRIVATE_KEY_MATERIAL =
      SecretBytes.copyFrom(
          Hex.decode("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
          InsecureSecretKeyAccess.get());
  private static final String SIGNATURE_HEX =
      "6291d657deec24024827e69c3abe01a3"
          + "0ce548a284743a445e3680d7db5ac3ac"
          + "18ff9b538d16f290ae67f760984dc659"
          + "4a7c15e9716ed28dc027beceea1ec40a";
  private static final Bytes MESSAGE = Bytes.copyFrom(Hex.decode("af82"));

  public static SignatureTestVector createTestVector0() throws GeneralSecurityException {
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.create(Ed25519Parameters.Variant.NO_PREFIX, PUBLIC_KEY_MATERIAL, null);
    Ed25519PrivateKey privateKey = Ed25519PrivateKey.create(publicKey, PRIVATE_KEY_MATERIAL);
    return new SignatureTestVector(privateKey, Hex.decode(SIGNATURE_HEX), MESSAGE.toByteArray());
  }

  public static SignatureTestVector createTestVector1() throws GeneralSecurityException {
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.create(Ed25519Parameters.Variant.TINK, PUBLIC_KEY_MATERIAL, 0x99887766);
    Ed25519PrivateKey privateKey = Ed25519PrivateKey.create(publicKey, PRIVATE_KEY_MATERIAL);
    return new SignatureTestVector(
        privateKey, Hex.decode("0199887766" + SIGNATURE_HEX), MESSAGE.toByteArray());
  }

  public static SignatureTestVector createTestVector2() throws GeneralSecurityException {
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.create(Ed25519Parameters.Variant.CRUNCHY, PUBLIC_KEY_MATERIAL, 0x99887766);
    Ed25519PrivateKey privateKey = Ed25519PrivateKey.create(publicKey, PRIVATE_KEY_MATERIAL);
    return new SignatureTestVector(
        privateKey, Hex.decode("0099887766" + SIGNATURE_HEX), MESSAGE.toByteArray());
  }

  // NOTE: This test vector has been generated adding a `0x00` suffix to the message.
  public static SignatureTestVector createTestVector3() throws GeneralSecurityException {
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.create(Ed25519Parameters.Variant.LEGACY, PUBLIC_KEY_MATERIAL, 0x99887766);
    Ed25519PrivateKey privateKey = Ed25519PrivateKey.create(publicKey, PRIVATE_KEY_MATERIAL);
    return new SignatureTestVector(
        privateKey,
        Hex.decode(
            "0099887766"
                + "afeae7a4fcd7d710a03353dfbe11a9906c6918633bb4dfef655d62d21f7535a1"
                + "108ea3ef5bef2b0d0acefbf0e051f62ee2582652ae769df983ad1b11a95d3a08"),
        MESSAGE.toByteArray());
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
