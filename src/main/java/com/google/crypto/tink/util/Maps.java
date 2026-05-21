package com.google.crypto.tink.util;

import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.toMap;

import java.util.AbstractMap;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

public final class Maps {
  @SafeVarargs
  public static <K, V> Map<K, V> ofEntries(Map.Entry<K, V>... entries) {
    return Arrays.stream(entries)
        .collect(
            collectingAndThen(
                toMap(Map.Entry::getKey, Map.Entry::getValue), Collections::unmodifiableMap));
  }

  public static <K, V> Map.Entry<K, V> entry(K k, V v) {
    return new AbstractMap.SimpleImmutableEntry<>(k, v);
  }

  private Maps() {}
}
