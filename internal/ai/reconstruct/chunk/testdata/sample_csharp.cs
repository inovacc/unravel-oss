namespace Sample.Ns
{
    [Obsolete]
    public class WithAttrs
    {
        public int X;

        public class Nested
        {
            public string S;
        }
    }

    public class Repo<T, U>
    {
        public T A;
        public U B;
    }

    public class Plain
    {
        public string M()
        {
            string s = "}";
            string r = @"} verbatim";
            var i = $"{X}";
            return s;
        }
    }
}
