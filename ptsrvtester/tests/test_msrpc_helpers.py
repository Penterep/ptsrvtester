import tempfile
import unittest
from pathlib import Path

from ptsrvtester.protocols.msrpc.utils.helpers import text_or_file


class MSRPCWordlistTests(unittest.TestCase):
    def read_values(self, content, *, preserve_whitespace=False):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "values.txt"
            path.write_bytes(content)
            return text_or_file(None, str(path), preserve_whitespace=preserve_whitespace)

    def test_direct_password_preserves_all_whitespace(self):
        for password in (" leading", "trailing ", " both ", " \t ", "\u00a0password\u00a0"):
            with self.subTest(password=repr(password)):
                self.assertEqual(
                    text_or_file(password, None, preserve_whitespace=True),
                    [password],
                )

    def test_password_wordlist_preserves_spaces_for_lf_crlf_and_cr(self):
        for newline in (b"\n", b"\r\n", b"\r"):
            with self.subTest(newline=newline):
                content = newline.join((b" leading", b"trailing ", b" \t ", b"last"))
                self.assertEqual(
                    self.read_values(content, preserve_whitespace=True),
                    [" leading", "trailing ", " \t ", "last"],
                )

    def test_password_wordlist_skips_only_empty_lines(self):
        self.assertEqual(
            self.read_values(b"\r\n \r\n\r\n\t\nvalue\n\n", preserve_whitespace=True),
            [" ", "\t", "value"],
        )

    def test_non_crlf_characters_do_not_split_passwords(self):
        password = "left\v\f\u0085\u2028\u2029right"
        self.assertEqual(
            self.read_values((password + "\n").encode("utf-8"), preserve_whitespace=True),
            [password],
        )

    def test_username_normalization_is_unchanged(self):
        self.assertEqual(text_or_file(" \talice \t", None), ["alice"])
        self.assertEqual(
            self.read_values(b" alice \r\n\r\n \t\nbob\v charlie \n"),
            ["alice", "bob", "charlie"],
        )
        self.assertEqual(text_or_file(" \t", None), [])

    def test_empty_direct_values_and_empty_files_remain_excluded(self):
        for preserve in (False, True):
            with self.subTest(preserve_whitespace=preserve):
                self.assertEqual(text_or_file("", None, preserve_whitespace=preserve), [])
                self.assertEqual(text_or_file(None, None, preserve_whitespace=preserve), [])
                self.assertEqual(self.read_values(b"", preserve_whitespace=preserve), [])

    def test_direct_password_takes_precedence_over_file(self):
        self.assertEqual(
            text_or_file(" secret ", "missing-file.txt", preserve_whitespace=True),
            [" secret "],
        )


if __name__ == "__main__":
    unittest.main()
