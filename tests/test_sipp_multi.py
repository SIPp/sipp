import importlib.util
from pathlib import Path
import os
import signal
import sys
import threading
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "sipp-multi.py"
SPEC = importlib.util.spec_from_file_location("sipp_multi", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
sipp_multi = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = sipp_multi
SPEC.loader.exec_module(sipp_multi)


class ConfigFile:
    def __init__(self, contents):
        self._directory = tempfile.TemporaryDirectory()
        self.path = Path(self._directory.name) / "multi.csv"
        self.path.write_text(contents, encoding="utf-8")

    def cleanup(self):
        self._directory.cleanup()


class ParseConfigTests(unittest.TestCase):
    def parse(self, contents):
        config = ConfigFile(contents)
        self.addCleanup(config.cleanup)
        return sipp_multi.parse_config(config.path)

    def test_accepts_header_after_comments_case_insensitively(self):
        specs = self.parse(
            "# generated\n\nRole,Count,Args\n"
            'uas,1,"-sn uas -nostdin"\n'
        )
        self.assertEqual(1, len(specs))
        self.assertEqual("uas", specs[0].role)
        self.assertEqual(("-sn", "uas", "-nostdin"), specs[0].args)

    def test_preserves_quoted_role_whitespace(self):
        specs = self.parse(
            "role,count,args\n"
            '"  spaced role  ",1,"-key role {role}"\n'
        )
        self.assertEqual("  spaced role  ", specs[0].role)

    def test_preserves_empty_quoted_argument(self):
        specs = self.parse(
            "role,count,args\n"
            'uas,1,"-key value \'\' tail"\n'
        )
        self.assertEqual(("-key", "value", "", "tail"), specs[0].args)

    def test_rejects_empty_args(self):
        with self.assertRaisesRegex(sipp_multi.ConfigError, "args must not be empty"):
            self.parse("role,count,args\nuas,1,\n")

    def test_rejects_unterminated_argument_quote(self):
        with self.assertRaisesRegex(sipp_multi.ConfigError, "No closing quotation"):
            self.parse('role,count,args\nuas,1,"-sn \'uas"\n')

    def test_rejects_invalid_count(self):
        with self.assertRaisesRegex(sipp_multi.ConfigError, "greater than zero"):
            self.parse('role,count,args\nuas,0,"-sn uas"\n')

    def test_rejects_more_than_256_children(self):
        with self.assertRaisesRegex(sipp_multi.ConfigError, "maximum of 256"):
            self.parse(
                "role,count,args\n"
                'uas,128,"-sn uas"\n'
                'uac,129,"-sn uac 127.0.0.1"\n'
            )


class BuildCommandsTests(unittest.TestCase):
    def spec(self, role, count, args):
        return sipp_multi.InstanceSpec(role, count, tuple(args))

    def test_expands_pairing_and_global_port_placeholders(self):
        commands = sipp_multi.build_commands(
            [
                self.spec("uas", 2, ["-sn", "uas", "-p", "{instance_port}"]),
                self.spec(
                    "uac",
                    2,
                    ["-sn", "uac", "127.0.0.1:{instance_port}", "-p", "{port}"],
                ),
            ],
            5060,
        )
        self.assertEqual("5060", commands[0].argv[-1])
        self.assertEqual("5061", commands[1].argv[-1])
        self.assertEqual("127.0.0.1:5060", commands[2].argv[2])
        self.assertEqual("5062", commands[2].argv[-1])
        self.assertEqual("5063", commands[3].argv[-1])

    def test_instance_numbers_continue_across_repeated_role_rows(self):
        commands = sipp_multi.build_commands(
            [
                self.spec("uas", 1, ["-key", "i", "{instance}"]),
                self.spec("uas", 1, ["-key", "i", "{instance}"]),
            ],
            5060,
        )
        self.assertEqual((0, 1), tuple(command.instance for command in commands))
        self.assertEqual(("0", "1"), tuple(command.argv[-1] for command in commands))

    def test_role_quote_is_expanded_without_resplitting(self):
        commands = sipp_multi.build_commands(
            [self.spec("ua's", 1, ["-key", "role", "{role}"])],
            5060,
        )
        self.assertEqual("ua's", commands[0].argv[-1])

    def test_rejects_port_overflow(self):
        with self.assertRaisesRegex(sipp_multi.ConfigError, "exceeds 65535"):
            sipp_multi.build_commands(
                [self.spec("uas", 2, ["-p", "{instance_port}"])],
                65535,
            )


class CommandLineTests(unittest.TestCase):
    def test_resolve_explicit_executable_with_shutil_which_semantics(self):
        self.assertEqual(
            str(Path(sys.executable).resolve()),
            sipp_multi.resolve_sipp_executable(sys.executable),
        )

    def test_resolve_rejects_non_executable_file(self):
        config = ConfigFile("not executable\n")
        self.addCleanup(config.cleanup)
        with self.assertRaisesRegex(sipp_multi.ConfigError, "unable to find executable"):
            sipp_multi.resolve_sipp_executable(str(config.path))

    def test_config_error_returns_one_without_usage_block(self):
        config = ConfigFile("role,count,args\nuas,not-a-number,\"-sn uas\"\n")
        self.addCleanup(config.cleanup)
        stderr = StringIO()
        with redirect_stderr(stderr):
            result = sipp_multi.main([str(config.path), "--sipp", sys.executable])
        self.assertEqual(1, result)
        self.assertIn("count must be a number", stderr.getvalue())
        self.assertNotIn("usage:", stderr.getvalue())

    def test_invalid_base_port_remains_a_cli_usage_error(self):
        parser = sipp_multi.build_arg_parser()
        stderr = StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            parser.parse_args(["multi.csv", "--base-port", "0"])
        self.assertEqual(2, raised.exception.code)
        self.assertIn("must be between 1 and 65535", stderr.getvalue())


class RuntimeTests(unittest.TestCase):
    def test_returns_first_nonzero_status_in_launch_order(self):
        commands = [
            sipp_multi.ChildCommand("a", 0, 5060, False, ("-c", "import sys; sys.exit(7)")),
            sipp_multi.ChildCommand("b", 0, 5061, False, ("-c", "import sys; sys.exit(3)")),
        ]
        self.assertEqual(7, sipp_multi.run_commands(sys.executable, commands))

    def test_successful_children_return_zero(self):
        commands = [
            sipp_multi.ChildCommand("a", 0, 5060, False, ("-c", "pass")),
            sipp_multi.ChildCommand("b", 0, 5061, False, ("-c", "pass")),
        ]
        self.assertEqual(0, sipp_multi.run_commands(sys.executable, commands))

    @unittest.skipIf(os.name == "nt", "POSIX signal delivery test")
    def test_sigterm_stops_children_and_returns_signal_status(self):
        commands = [
            sipp_multi.ChildCommand(
                "a",
                0,
                5060,
                False,
                ("-c", "import time; time.sleep(30)"),
            )
        ]
        timer = threading.Timer(
            0.5, lambda: os.kill(os.getpid(), signal.SIGTERM)
        )
        timer.start()
        try:
            self.assertEqual(
                128 + signal.SIGTERM,
                sipp_multi.run_commands(sys.executable, commands),
            )
        finally:
            timer.cancel()


if __name__ == "__main__":
    unittest.main()
