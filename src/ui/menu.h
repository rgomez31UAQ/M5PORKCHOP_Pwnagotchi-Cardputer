// Menu system
#pragma once

#include <Arduino.h>
#include <M5Unified.h>
#include <vector>
#include <functional>

struct MenuItem {
    String label;
    uint8_t actionId;
};

using MenuCallback = std::function<void(uint8_t actionId)>;

class Menu {
public:
    static void init();
    static void update();
    static void draw(M5Canvas& canvas);
    
    static void setItems(const std::vector<MenuItem>& items);
    static void setTitle(const String& title);
    static void setCallback(MenuCallback cb);
    
    static int getSelectedId();
    static bool isActive() { return active; }
    static bool wasSelected() { return selected; }
    static void clearSelected() { selected = false; }
    static void show();
    static void hide();
    
private:
    static std::vector<MenuItem> menuItems;
    static String menuTitle;
    static uint8_t selectedIndex;
    static uint8_t scrollOffset;
    static bool active;
    static bool selected;
    static MenuCallback callback;
    static bool keyWasPressed;  // Debounce tracking
    
    static const uint8_t VISIBLE_ITEMS = 5;  // Fits without nav instructions
    
    static void handleInput();
};
