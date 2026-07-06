function foo(x) {
    const s = `}${x}`;
    // }
    return s;
}

function bar(y) {
    const r = /\}/g;
    const z = y / 2;
    return r.test(String(z));
}

class Bar {
    constructor() {
        this.value = 0;
    }

    method() {
        return this.value;
    }
}
