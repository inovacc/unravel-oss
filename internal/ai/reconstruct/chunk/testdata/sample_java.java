package com.example.app;

import java.util.List;
import java.util.Map;

@Deprecated
public class Alpha {
    public int x;
    public String y;

    public static class Nested {
        public int z;
    }
}

public class Repository<T, U> {
    public T find(String id) {
        return null;
    }

    public String text() {
        String s = "}";
        String t = "// not a comment";
        // real } comment
        /* } block */
        return s;
    }
}

public class Beta {
    public String build() {
        String tb = """
}
""";
        return tb;
    }
}
