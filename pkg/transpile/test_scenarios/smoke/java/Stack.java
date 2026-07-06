// Vendored smoke-corpus fixture (D-03 / SC3). Small, self-contained,
// license-clean Java source: a generic bounded stack. No external build
// dependency. See test_scenarios/smoke/SOURCES.md for provenance/pinning.
package smoke;

import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;

public class Stack<T> {
    private final List<T> items = new ArrayList<>();
    private final int capacity;

    public Stack(int capacity) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("capacity must be positive");
        }
        this.capacity = capacity;
    }

    public boolean isEmpty() {
        return items.isEmpty();
    }

    public boolean isFull() {
        return items.size() >= capacity;
    }

    public int size() {
        return items.size();
    }

    public void push(T value) {
        if (isFull()) {
            throw new IllegalStateException("stack overflow");
        }
        items.add(value);
    }

    public T pop() {
        if (isEmpty()) {
            throw new NoSuchElementException("stack underflow");
        }
        return items.remove(items.size() - 1);
    }

    public T peek() {
        if (isEmpty()) {
            throw new NoSuchElementException("stack is empty");
        }
        return items.get(items.size() - 1);
    }

    public void clear() {
        items.clear();
    }
}
