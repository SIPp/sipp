## What makes a PR mergeable

The maintainers have little time, so a PR that ticks most of these boxes
is much more likely to be reviewed and merged:

- Without the change, SIPp is worse than with it.
- The change follows the coding standards (see below), and the commit
  message explains *why* it is needed, not only what it does.
- It consolidates existing features rather than adding yet another one,
  so the code stays maintainable.
- Changed or new behaviour is documented, both in the CLI help
  (`sipp -h`, in `src/sipp.cpp`) and in the RST docs under `docs/`.
- It stays backward compatible, or says clearly what breaks, so that
  upgrading to the next SIPp version is not a hassle.
- It comes with a test: a regression test under `regress/` (see
  `regress/runtests`) for behaviour visible from the command line, or a
  unit test (`make sipp_unittest`) for internal functions.
- It does not promise more than SIPp delivers.
- A maintainer is affected by the change, or the PR makes a compelling
  case for it.

## Code Formatting

This project uses [clang-format](https://clang.llvm.org/docs/ClangFormat.html) to maintain consistent code style. CI checks that the lines each pull request changes follow it. Much of the existing code predates this style, so leave the lines you don't change as they are.

### Setup

Install clang-format (CI uses the version Ubuntu 26.04 ships):

```bash
# Ubuntu/Debian
sudo apt install clang-format

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

Format only the lines you changed since master, as CI checks them:

```bash
git clang-format origin/master
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
