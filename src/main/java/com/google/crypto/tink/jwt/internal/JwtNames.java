// Copyright 2020 Google LLC
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

package com.google.crypto.tink.jwt.internal;

/** Static utilities for dealing with claim names. */
public final class JwtNames {
  /**
   * Registered claim names, as defined in https://tools.ietf.org/html/rfc7519#section-4.1. If
   * update, please update validateClaim().
   */
  public static final String CLAIM_ISSUER = "iss";

  public static final String CLAIM_SUBJECT = "sub";
  public static final String CLAIM_AUDIENCE = "aud";
  public static final String CLAIM_EXPIRATION = "exp";
  public static final String CLAIM_NOT_BEFORE = "nbf";
  public static final String CLAIM_ISSUED_AT = "iat";
  public static final String CLAIM_JWT_ID = "jti";

  /**
   * Supported protected headers, as described in https://tools.ietf.org/html/rfc7515#section-4.1
   */
  public static final String HEADER_ALGORITHM = "alg";

  public static final String HEADER_KEY_ID = "kid";
  public static final String HEADER_TYPE = "typ";
  public static final String HEADER_CRITICAL = "crit";

  public static void validate(String name) {
    if (isRegisteredName(name)) {
      throw new IllegalArgumentException(
          String.format(
              "claim '%s' is invalid because it's a registered name; use the corresponding"
                  + " setter method.",
              name));
    }
  }

  public static boolean isRegisteredName(String name) {
    return name.equals(CLAIM_ISSUER)
        || name.equals(CLAIM_SUBJECT)
        || name.equals(CLAIM_AUDIENCE)
        || name.equals(CLAIM_EXPIRATION)
        || name.equals(CLAIM_NOT_BEFORE)
        || name.equals(CLAIM_ISSUED_AT)
        || name.equals(CLAIM_JWT_ID);
  }

  private JwtNames() {}
}
