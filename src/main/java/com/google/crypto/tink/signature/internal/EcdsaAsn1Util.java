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
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.internal.Asn1Util;
import com.google.crypto.tink.internal.BigIntegerEncoding;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

/** ASN.1 SEC1 EC private key encoding helpers. */
public final class EcdsaAsn1Util {
  /**
   * The values of the tags below are specified in the Sections 8.1.2.2 -- 8.1.2.5 of ITU-T X.690,
   * and are
   * 0x80 (context-specific) | 0x20 (constructed) | NUMBER
   * where NUMBER is 0 for [0] and 1 for [1], which gives us tag values 0xa0 and 0xa1 respectively.
   *
   * These explicit context-specific constructed tags are used by SEC.1 in the optional private key
   * fields (parameters and public key). The ASN.1 SEC1 encoded private key, as per Sections C.4 and
   * C.8 of SEC 1 v2.0 (https://www.secg.org/sec1-v2.pdf) and RFC 5915 Section 3 and Appendix A,
   * looks like the following:
   *
   * <pre>{@code
   * ECPrivateKey ::= SEQUENCE {
   *   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
   *   privateKey     OCTET STRING,
   *   parameters [0] EXPLICIT ECParameters OPTIONAL,
   *   publicKey  [1] EXPLICIT BIT STRING OPTIONAL
   * }
   * }</pre>
   *
   * The tags [0]/[1] are explicit context-specific constructed tags, as per the formal definition
   * in ITU-T Rec. X.680 Clauses 31.2.1 and 31.2.4. The definition for the explicit tag format can
   * be found in the Section 8.14.3 of ITU-T Rec. X.690.
   */
  private static final byte TAG_CONTEXT_SPECIFIC_0 = (byte) 0xa0;

  // Value from https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1.1
  private static final byte[] p256Oid =
      new byte[] {0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07};
  // Value from https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1.1
  private static final byte[] p384Oid = new byte[] {0x2b, (byte) 0x81, 0x04, 0x00, 0x22};
  // Value from https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1.1
  private static final byte[] p521Oid = new byte[] {0x2b, (byte) 0x81, 0x04, 0x00, 0x23};

  // Wraps a given OID into the explicit context-specific constructed tag [0] ECParameters, as per
  // the https://www.rfc-editor.org/rfc/rfc5915.html#section-3 (specifies the field) and
  // https://www.rfc-editor.org/rfc/rfc5915.html#appendix-A (instructs the use of explicit tags).
  private static byte[] createExplicitlyTaggedOid(byte[] oid) {
    byte[] encodedOid = new byte[oid.length + 2];
    encodedOid[0] = Asn1Util.TAG_OBJECT_IDENTIFIER;
    encodedOid[1] = (byte) oid.length;
    System.arraycopy(oid, 0, encodedOid, 2, oid.length);

    byte[] tagged = new byte[encodedOid.length + 2];
    tagged[0] = TAG_CONTEXT_SPECIFIC_0;
    tagged[1] = (byte) encodedOid.length;
    System.arraycopy(encodedOid, 0, tagged, 2, encodedOid.length);
    return tagged;
  }

  private EcdsaAsn1Util() {}

  /**
   * Takes a Tink {@link EcdsaPrivateKey} and returns the ASN.1 SEC1 encoded private key as per RFC
   * 5915 Section 3 and Appendix A (and Sections C.4 and C.8 of https://www.secg.org/sec1-v2.pdf):
   *
   * <pre>{@code
   * ECPrivateKey ::= SEQUENCE {
   *   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
   *   privateKey     OCTET STRING,
   *   parameters [0] EXPLICIT ECParameters OPTIONAL,
   *   publicKey  [1] EXPLICIT BIT STRING OPTIONAL
   * }
   * }</pre>
   *
   * with version set to 1, named curve parameters present, and publicKey absent.
   *
   * <p>Requires {@link EcdsaParameters.Variant#NO_PREFIX}, {@link
   * EcdsaParameters.SignatureEncoding#DER}, and the hash type matching the curve as per
   * https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html (SHA256
   * for NIST_P256, SHA384 for NIST_P384, SHA512 for NIST_P521).
   */
  @AccessesPartialKey
  public static byte[] ecdsaPrivateKeyToSec1Bytes(EcdsaPrivateKey key, SecretKeyAccess access)
      throws GeneralSecurityException {
    EcdsaParameters params = key.getParameters();
    if (params.getVariant() != EcdsaParameters.Variant.NO_PREFIX) {
      throw new GeneralSecurityException(
          "Unsupported ECDSA variant for SEC1 encoding: " + params.getVariant());
    }
    if (params.getSignatureEncoding() != EcdsaParameters.SignatureEncoding.DER) {
      throw new GeneralSecurityException(
          "Unsupported ECDSA signature encoding for SEC1 encoding: "
              + params.getSignatureEncoding());
    }

    EcdsaParameters.CurveType curveType = params.getCurveType();
    EcdsaParameters.HashType hashType = params.getHashType();
    byte[] oidTagged;
    int fieldSize;
    if (curveType == EcdsaParameters.CurveType.NIST_P256) {
      if (hashType != EcdsaParameters.HashType.SHA256) {
        throw new GeneralSecurityException(
            "Unsupported hash type for NIST_P256 in SEC1 encoding: " + hashType);
      }
      oidTagged = createExplicitlyTaggedOid(p256Oid);
      fieldSize = 32;
    } else if (curveType == EcdsaParameters.CurveType.NIST_P384) {
      if (hashType != EcdsaParameters.HashType.SHA384) {
        throw new GeneralSecurityException(
            "Unsupported hash type for NIST_P384 in SEC1 encoding: " + hashType);
      }
      oidTagged = createExplicitlyTaggedOid(p384Oid);
      fieldSize = 48;
    } else if (curveType == EcdsaParameters.CurveType.NIST_P521) {
      if (hashType != EcdsaParameters.HashType.SHA512) {
        throw new GeneralSecurityException(
            "Unsupported hash type for NIST_P521 in SEC1 encoding: " + hashType);
      }
      oidTagged = createExplicitlyTaggedOid(p521Oid);
      fieldSize = 66;
    } else {
      throw new GeneralSecurityException("Unsupported curve type: " + curveType);
    }
    List<byte[]> elements = new ArrayList<>();
    elements.add(Asn1Util.createInteger(BigInteger.ONE));
    elements.add(
        Asn1Util.createOctetString(
            BigIntegerEncoding.toBigEndianBytesOfFixedLength(
                key.getPrivateValue().getBigInteger(SecretKeyAccess.requireAccess(access)),
                fieldSize)));
    elements.add(oidTagged);
    return Asn1Util.createSequence(elements);
  }
}
