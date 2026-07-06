import java.io.StringReader;

public class DetTryWithResources {
    public int read(String data) throws Exception {
        try (StringReader r = new StringReader(data)) {
            return r.read();
        }
    }
}
