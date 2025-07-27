#pragma once
#include <iostream>
#include <vector>
#include <string>

void print_side_by_side_green(const std::vector<std::string>& left_art,
                             const std::vector<std::string>& right_art,
                             int gap = 0) {
    std::string spacer(gap, ' ');
    const std::string green_start = "\033[32m";
    const std::string color_end = "\033[0m";

    size_t max_lines = std::max(left_art.size(), right_art.size());

    for (size_t i = 0; i < max_lines; ++i) {
        std::string left_line = i < left_art.size() ? left_art[i] : "";
        std::string right_line = i < right_art.size() ? right_art[i] : "";

        std::cout << green_start << left_line << spacer << right_line << color_end << "\n";
    }
}

void printAscii() {
    std::vector<std::string> new_image = {
        "                         ",
        "            ▒▒░          ",
        "      █░▒░░▒█▒▒█▒░░      ",
        "      █ ▒█▓▓█▓▒▒██▓      ",
        "       ▒█ ██ █░░▒░█▓░    ",
        "     █▒██ ██ ████░▓█▓    ",
        "    ░█▓  █   ██ █░██▓    ",
        "    ▓█▓    ░    █░██▓    ",
        "    ▒█ ██      █▓░█▓▒    ",
        "       █████ █████       ",
        "       ▒▓█▒████▒▓▒█      ",
        "       ░▒▓█▓█▒█▓▓░▒      ",
        "          ▒░█░▒          ",
        "                         ",
    };

    std::vector<std::string> ascii_art = {
        "                                                           ",
        "                                                           ",
        "                                                           ",
        "                                                           ",
        "                                                           ",
        "  $$$$$\\                                          $$\\     ",
        "  \\__$$ |                                         $$ |    ",
        "     $$ | $$$$$$\\  $$$$$$$\\  $$$$$$$\\   $$$$$$\\ $$$$$$\\   ",
        "     $$ |$$  __$$\\ $$  __$$\\ $$  __$$\\ $$  __$$\\ \\_$$  _|  ",
        "$$\\   $$ |$$$$$$$$ |$$ |  $$ |$$ |  $$ |$$$$$$$$ | $$ |    ",
        "$$ |  $$ |$$   ____|$$ |  $$ |$$ |  $$ |$$   ____| $$ |$$\\ ",
        "\\$$$$$$  |\\$$$$$$$\\ $$ |  $$ |$$ |  $$ |\\$$$$$$$\\  \\$$$$  |",
        " \\______/  \\_______|\\__|  \\__|\\__|  \\__| \\_______|  \\____/ ",
        "                                                           ",
        "                                                           ",
    };

    print_side_by_side_green(new_image, ascii_art);
}
