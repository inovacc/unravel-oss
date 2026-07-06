package com.example;

import java.util.ArrayList;
import java.util.List;

public class SimpleClass {
    private String name;
    private int count;
    private List<String> items;

    public SimpleClass(String name) {
        this.name = name;
        this.count = 0;
        this.items = new ArrayList<>();
    }

    public void addItem(String item) {
        items.add(item);
        count++;
    }

    public String getName() {
        return name;
    }

    public int getCount() {
        return count;
    }

    public List<String> getItems() {
        return items;
    }

    @Override
    public String toString() {
        return "SimpleClass{name='" + name + "', count=" + count + "}";
    }

    public static void main(String[] args) {
        SimpleClass obj = new SimpleClass("test");
        obj.addItem("hello");
        obj.addItem("world");
        System.out.println(obj);
    }
}
