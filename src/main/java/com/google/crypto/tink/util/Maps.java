package com.google.crypto.tink.util;

import java.util.AbstractMap;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

public final class Maps {
  @SafeVarargs
  public static <K, V> Map<K, V> ofEntries(Map.Entry<K, V>... entries) {
    return Arrays.stream(entries).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
  }

  public static <K, V> Map.Entry<K, V> entry(K k, V v) {
    return new AbstractMap.SimpleImmutableEntry<>(k, v);
  }

  private Maps() {}
}
