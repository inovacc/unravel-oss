// Hand-authored sample: 3 top-level types + nested + attributes + generics + tricky braces.
namespace Sample.Ns
{
    [Serializable]
    [Obsolete("legacy")]
    public class WithAttrs
    {
        public int X;

        // } trick comment with brace
        /* block comment with } */
        public string M()
        {
            string s = "}";
            string a = @"raw }";
            var i = $"{X}";
            return s + a + i;
        }

        public class Nested
        {
            public int Y;
        }
    }

    public class Repo<T, U>
    {
        public T A;
        public U B;
        public Repo(T a, U b) { A = a; B = b; }
    }

    internal sealed class Plain
    {
        public void Run() { /* noop */ }
    }
}
