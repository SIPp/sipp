/*
 * Multi-instance launcher support for SIPp.
 */

#include "multi_instance.hpp"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <sstream>

static std::string trim_copy(const std::string &value)
{
    size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return "";
    }
    size_t last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

static bool parse_csv_line(const std::string &line,
                           std::vector<std::string> *fields,
                           std::string *error)
{
    fields->clear();
    std::string current;
    bool in_quotes = false;

    for (size_t i = 0; i < line.size(); ++i) {
        char ch = line[i];
        if (in_quotes) {
            if (ch == '"') {
                if ((i + 1 < line.size()) && line[i + 1] == '"') {
                    current.push_back('"');
                    ++i;
                } else {
                    in_quotes = false;
                }
            } else {
                current.push_back(ch);
            }
        } else if (ch == '"') {
            in_quotes = true;
        } else if (ch == ',') {
            fields->push_back(trim_copy(current));
            current.clear();
        } else {
            current.push_back(ch);
        }
    }

    if (in_quotes) {
        *error = "unterminated quoted CSV field";
        return false;
    }

    fields->push_back(trim_copy(current));
    return true;
}

static bool split_args(const std::string &args,
                       std::vector<std::string> *words,
                       std::string *error)
{
    words->clear();
    std::string current;
    char quote = 0;
    bool escaping = false;

    for (char ch : args) {
        if (escaping) {
            current.push_back(ch);
            escaping = false;
            continue;
        }
        if (ch == '\\') {
            escaping = true;
            continue;
        }
        if (quote) {
            if (ch == quote) {
                quote = 0;
            } else {
                current.push_back(ch);
            }
            continue;
        }
        if (ch == '\'' || ch == '"') {
            quote = ch;
        } else if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
            if (!current.empty()) {
                words->push_back(current);
                current.clear();
            }
        } else {
            current.push_back(ch);
        }
    }

    if (escaping) {
        current.push_back('\\');
    }
    if (quote) {
        *error = "unterminated quoted argument";
        return false;
    }
    if (!current.empty()) {
        words->push_back(current);
    }

    return true;
}

static void replace_all(std::string *value,
                        const std::string &needle,
                        const std::string &replacement)
{
    size_t pos = 0;
    while ((pos = value->find(needle, pos)) != std::string::npos) {
        value->replace(pos, needle.size(), replacement);
        pos += replacement.size();
    }
}

bool parse_multi_instance_csv(const std::string &csv,
                              const std::string &source_name,
                              std::vector<MultiInstanceSpec> *specs,
                              std::string *error)
{
    specs->clear();
    std::istringstream input(csv);
    std::string line;
    int line_number = 0;

    while (std::getline(input, line)) {
        ++line_number;
        if (!line.empty() && line[line.size() - 1] == '\r') {
            line.erase(line.size() - 1);
        }
        std::string trimmed = trim_copy(line);
        if (trimmed.empty() || trimmed[0] == '#') {
            continue;
        }

        std::vector<std::string> fields;
        std::string parse_error;
        if (!parse_csv_line(line, &fields, &parse_error)) {
            *error = source_name + ":" + std::to_string(line_number) + ": " + parse_error;
            return false;
        }

        if (fields.size() != 3) {
            *error = source_name + ":" + std::to_string(line_number) +
                     ": expected role,count,args";
            return false;
        }

        if (line_number == 1 && fields[0] == "role" && fields[1] == "count" &&
            fields[2] == "args") {
            continue;
        }

        char *end = nullptr;
        long count = strtol(fields[1].c_str(), &end, 10);
        if (*end != '\0') {
            *error = source_name + ":" + std::to_string(line_number) +
                     ": count must be a number";
            return false;
        }
        if (count <= 0) {
            *error = source_name + ":" + std::to_string(line_number) +
                     ": count must be greater than zero";
            return false;
        }
        if (fields[0].empty()) {
            *error = source_name + ":" + std::to_string(line_number) +
                     ": role must not be empty";
            return false;
        }

        std::vector<std::string> unused_words;
        if (!split_args(fields[2], &unused_words, error)) {
            *error = source_name + ":" + std::to_string(line_number) + ": " + *error;
            return false;
        }

        MultiInstanceSpec spec;
        spec.role = fields[0];
        spec.count = static_cast<int>(count);
        spec.args = fields[2];
        specs->push_back(spec);
    }

    if (specs->empty()) {
        *error = source_name + ": no multi-instance rows found";
        return false;
    }

    return true;
}

bool parse_multi_instance_csv_file(const std::string &path,
                                   std::vector<MultiInstanceSpec> *specs,
                                   std::string *error)
{
    std::ifstream file(path);
    if (!file.good()) {
        *error = "unable to open multi-instance file: " + path;
        return false;
    }

    std::ostringstream contents;
    contents << file.rdbuf();
    return parse_multi_instance_csv(contents.str(), path, specs, error);
}

std::vector<MultiInstanceCommand>
build_multi_instance_commands(const std::string &program_path,
                              const std::vector<MultiInstanceSpec> &specs,
                              int base_port)
{
    std::vector<MultiInstanceCommand> commands;
    int next_port = base_port;

    for (const MultiInstanceSpec &spec : specs) {
        for (int instance = 0; instance < spec.count; ++instance) {
            std::string expanded = spec.args;
            int instance_port = base_port + instance;
            replace_all(&expanded, "{role}", spec.role);
            replace_all(&expanded, "{instance}", std::to_string(instance));
            replace_all(&expanded, "{instance_port}", std::to_string(instance_port));
            replace_all(&expanded, "{base_port}", std::to_string(base_port));
            replace_all(&expanded, "{port}", std::to_string(next_port));

            std::vector<std::string> words;
            std::string error;
            if (!split_args(expanded, &words, &error)) {
                words.clear();
            }

            MultiInstanceCommand command;
            command.role = spec.role;
            command.instance = instance;
            command.port = next_port;
            command.argv.push_back(program_path);
            command.argv.insert(command.argv.end(), words.begin(), words.end());
            commands.push_back(command);
            ++next_port;
        }
    }

    return commands;
}

int run_multi_instance_commands(const std::vector<MultiInstanceCommand> &commands,
                                std::ostream &out,
                                std::ostream &err)
{
    std::vector<pid_t> children;
    int exit_code = 0;

    for (const MultiInstanceCommand &command : commands) {
        out << "Starting " << command.role << "[" << command.instance << "]";
        if (command.port > 0) {
            out << " port=" << command.port;
        }
        out << ":";
        for (const std::string &arg : command.argv) {
            out << " " << arg;
        }
        out << "\n";
        out.flush();

        pid_t child = fork();
        if (child < 0) {
            err << "fork failed: " << strerror(errno) << "\n";
            exit_code = 1;
            break;
        }
        if (child == 0) {
            std::vector<char *> argv;
            argv.reserve(command.argv.size() + 1);
            for (const std::string &arg : command.argv) {
                argv.push_back(const_cast<char *>(arg.c_str()));
            }
            argv.push_back(nullptr);
            execvp(argv[0], argv.data());
            std::cerr << "exec failed for " << argv[0] << ": " << strerror(errno) << "\n";
            _exit(127);
        }
        children.push_back(child);
    }

    for (pid_t child : children) {
        int status = 0;
        while (waitpid(child, &status, 0) < 0) {
            if (errno != EINTR) {
                err << "waitpid failed for " << child << ": " << strerror(errno) << "\n";
                exit_code = 1;
                break;
            }
        }
        if (WIFEXITED(status)) {
            int child_exit = WEXITSTATUS(status);
            if (child_exit != 0 && exit_code == 0) {
                exit_code = child_exit;
            }
        } else if (WIFSIGNALED(status)) {
            int signal_number = WTERMSIG(status);
            if (exit_code == 0) {
                exit_code = 128 + signal_number;
            }
        }
    }

    return exit_code;
}
