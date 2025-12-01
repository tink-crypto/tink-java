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

package com.google.crypto.tink.signature;

import com.google.errorprone.annotations.Immutable;
import java.util.Objects;

/** Describes the parameters of SLH-DSA signature primitive. */
public class SlhDsaParameters extends SignatureParameters {

  /**
   * Describes details of the SLH-DSA signature format.
   *
   * <p>The standard SLH-DSA key is used for variant "NO_PREFIX". "TINK" adds a prefix to every
   * computation depending on the key id.
   */
  @Immutable
  public static final class Variant {
    public static final Variant TINK = new Variant("TINK");
    public static final Variant NO_PREFIX = new Variant("NO_PREFIX");

    private final String name;

    private Variant(String name) {
      this.name = name;
    }

    @Override
    public String toString() {
      return name;
    }
  }

  /** SLH-DSA hash type. */
  @Immutable
  public static final class HashType {
    public static final HashType SHA2 = new HashType("SHA2");
    public static final HashType SHAKE = new HashType("SHAKE");

    private final String name;

    private HashType(String name) {
      this.name = name;
    }

    @Override
    public String toString() {
      return name;
    }
  }

  /** What the SLH-DSA signing is optimized for. */
  @Immutable
  public static final class SignatureType {
    public static final SignatureType FAST_SIGNING = new SignatureType("F");
    public static final SignatureType SMALL_SIGNATURE = new SignatureType("S");

    private final String name;

    private SignatureType(String name) {
      this.name = name;
    }

    @Override
    public String toString() {
      return name;
    }
  }

  public static final int SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES = 64;

  private final HashType hashType;
  private final SignatureType signatureType;
  private final Variant variant;
  private final int privateKeySize;

  /**
   * Create an SLH-DSA-SHA2-128S parameters with a given variant.
   *
   * <p>The other configurations are currently not supported.
   */
  public static SlhDsaParameters createSlhDsaWithSha2And128S(Variant variant) {
    return new SlhDsaParameters(
        HashType.SHA2, SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES, SignatureType.SMALL_SIGNATURE, variant);
  }

  private SlhDsaParameters(
      HashType hashType, int privateKeySizeBytes, SignatureType signatureType, Variant variant) {
    this.hashType = hashType;
    this.privateKeySize = privateKeySizeBytes;
    this.signatureType = signatureType;
    this.variant = variant;
  }

  public HashType getHashType() {
    return hashType;
  }

  public SignatureType getSignatureType() {
    return signatureType;
  }

  public Variant getVariant() {
    return variant;
  }

  public int getPrivateKeySize() {
    return privateKeySize;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof SlhDsaParameters)) {
      return false;
    }
    SlhDsaParameters other = (SlhDsaParameters) o;
    return other.getHashType() == getHashType()
        && other.getSignatureType() == getSignatureType()
        && other.getVariant() == getVariant()
        && other.getPrivateKeySize() == getPrivateKeySize();
  }

  @Override
  public int hashCode() {
    return Objects.hash(SlhDsaParameters.class, hashType, privateKeySize, signatureType, variant);
  }

  @Override
  public boolean hasIdRequirement() {
    return variant != Variant.NO_PREFIX;
  }

  @Override
  public String toString() {
    return "SLH-DSA-"
        + hashType.toString()
        + "-"
        + privateKeySize * 2
        + signatureType
        + " instance, variant: "
        + variant;
  }
}
