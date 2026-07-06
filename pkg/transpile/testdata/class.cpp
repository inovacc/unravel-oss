#include <string>
#include <iostream>

class Person {
private:
    std::string name;
    int age;

public:
    Person(const std::string& n, int a) : name(n), age(a) {}
    ~Person() { std::cout << "Destroying " << name << std::endl; }

    std::string getName() const { return name; }
    int getAge() const { return age; }
    void setAge(int a) { age = a; }

    bool operator==(const Person& other) const {
        return name == other.name && age == other.age;
    }
};

int main() {
    Person p("Alice", 30);
    std::cout << p.getName() << " is " << p.getAge() << std::endl;
    return 0;
}
