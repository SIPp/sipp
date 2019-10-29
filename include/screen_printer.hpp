#include <stdio.h>
#include <unistd.h>
#include <string>
#include <vector>


class ScreenPrinter {
public:
    ScreenPrinter():
        M_headless(!isatty(fileno(stdout)))
    {};
    void redraw();
    void print_closing_stats();
    void print_to_file(FILE* f);
    bool M_headless;

private:
    void get_lines();
    void draw_scenario_screen();
    void draw_tdm_screen();
    void draw_vars_screen();
    std::vector<std::string> lines;

    bool M_last = false;
};

extern ScreenPrinter* sp;
