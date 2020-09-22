/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  Copyright (C) 2003 - The Authors
 *
 *  Author : Richard GAYRAUD - 04 Nov 2003
 *           From Hewlett Packard Company.
 */

/****
 * Screen.hpp : Simple curses & logfile encapsulation
 */

#ifndef __SCREEN_H__
#define __SCREEN_H__

#include <stdio.h>
#include <unistd.h>
#include <string>
#include <vector>

#include "defines.h"
#include "stat.hpp"

void screen_init();
void screen_clear();
int  screen_readkey();
void screen_exit();
void print_statistics(int last);

extern int key_backspace;
extern int key_dc;

class ScreenPrinter {
public:
    ScreenPrinter():
        M_headless(!isatty(fileno(stdout))),
        M_last(false)
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
    void draw_stats_screen();
    void draw_repartition_screen(int which);
    void draw_repartition_detailed(CStat::T_dynamicalRepartition * tabRepartition,
                                 int sizeOfTab);

    std::vector<std::string> lines;

    bool M_last;
};

extern ScreenPrinter* sp;

#endif // __SCREEN_H__
