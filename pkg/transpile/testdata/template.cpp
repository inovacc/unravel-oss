#include <iostream>
#include <vector>
#include <algorithm>

template <typename T>
class Stack {
private:
    std::vector<T> data;

public:
    void push(const T& value) { data.push_back(value); }
    T pop() {
        T top = data.back();
        data.pop_back();
        return top;
    }
    bool empty() const { return data.empty(); }
    size_t size() const { return data.size(); }
};

int main() {
    Stack<int> s;
    s.push(1);
    s.push(2);
    s.push(3);
    while (!s.empty()) {
        std::cout << s.pop() << std::endl;
    }
    return 0;
}
