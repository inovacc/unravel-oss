package com.example.app;

import java.util.ArrayList;
import java.util.List;

/* renamed from: com.example.app.DataManager */
public class DataManager {

    /* access modifiers changed from: private */
    public List<String> items;

    /* goto */ /* JADX WARNING: Code restructure failed */
    public void processItems() {
        label_0:
        int i = 0;
        /* goto */ label_1:
        while (i < this.items.size()) {
            String item = this.items.get(i);
            if (item == null) {
                /* goto */ label_0;
                continue;
            }
            label_1:
            System.out.println(item.trim());
            i++;
        }
    }

    static /* synthetic */ List access$000(DataManager x0) {
        return x0.items;
    }

    static /* synthetic */ void access$100(DataManager x0, String x1) {
        x0.items.add(x1);
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
