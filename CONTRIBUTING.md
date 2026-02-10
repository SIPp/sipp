## Code Formatting

This project uses [clang-format](https://clang.llvm.org/docs/ClangFormat.html) to maintain consistent code style. Pull requests are automatically checked for formatting compliance.

### Setup

Install clang-format (version 18 recommended):

```bash
# Ubuntu/Debian
sudo apt install clang-format-18

# macOS
brew install clang-format

# Fedora
sudo dnf install clang-tools-extra
```

### Usage

Format a single file:

```bash
clang-format -i src/myfile.cpp
```

Format all source files:

```bash
find src include -type f \( -name '*.cpp' -o -name '*.hpp' -o -name '*.c' -o -name '*.h' \) | xargs clang-format -i
```

Check formatting without modifying files:

```bash
clang-format --dry-run --Werror src/myfile.cpp
```

### Editor Integration

Most editors support automatic formatting on save:

- **VS Code**: Install the "C/C++" extension, enable "Format On Save"
- **CLion**: Built-in support, enable in Settings → Editor → Code Style
- **Vim**: Use [vim-clang-format](https://github.com/rhysd/vim-clang-format)
- **Emacs**: Use [clang-format.el](https://clang.llvm.org/docs/ClangFormat.html#emacs-integration)

### Style Overview

The project uses a style based on LLVM with these key settings:

- 4-space indentation (no tabs)
- Allman/BSD brace style (braces on their own lines)
- 120 character line limit
- Pointer/reference aligned right (`char *ptr`, not `char* ptr`)
- Includes are not sorted (to avoid breaking builds)

See `.clang-format` in the repository root for the complete configuration.
