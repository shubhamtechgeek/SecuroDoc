package com.application.SecuroDoc.function;

import java.util.Objects;
import java.util.function.Consumer;

@FunctionalInterface
public interface TriConsumer<T, U, V> {
    void accept(T t, U u, V v);
}
