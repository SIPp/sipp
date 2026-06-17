/*
 * Multi-instance launcher support for SIPp.
 */

#ifndef __MULTI_INSTANCE__
#define __MULTI_INSTANCE__

#include <iosfwd>
#include <string>
#include <vector>

struct MultiInstanceSpec {
    std::string role;
    int count;
    std::string args;
};

struct MultiInstanceCommand {
    std::string role;
    int instance;
    int port;
    std::vector<std::string> argv;
};

bool parse_multi_instance_csv(const std::string &csv,
                              const std::string &source_name,
                              std::vector<MultiInstanceSpec> *specs,
                              std::string *error);

bool parse_multi_instance_csv_file(const std::string &path,
                                   std::vector<MultiInstanceSpec> *specs,
                                   std::string *error);

std::vector<MultiInstanceCommand>
build_multi_instance_commands(const std::string &program_path,
                              const std::vector<MultiInstanceSpec> &specs,
                              int base_port);

int run_multi_instance_commands(const std::vector<MultiInstanceCommand> &commands,
                                std::ostream &out,
                                std::ostream &err);

#endif
