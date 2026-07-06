package com.example.app;

import java.util.ArrayList;
import java.util.List;

/* renamed from: com.example.app.DataManager */
public class DataManager {

    /* access modifiers changed from: private */
    public List<String> items;

    public void processItems() {

        int i = 0;

        while (i < this.items.size()) {
            String item = this.items.get(i);
            if (item == null) {

                continue;
            }

            System.out.println(item.trim());
            i++;
        }
    }

    public DataManager() {
        this.items = new ArrayList<>();
    }

    public void addItem(String item) {
        if (item != null && !item.isEmpty()) {
            this.items.add(item);
        }
    }

    public int getCount() {
        return this.items.size();
    }
}
