"""The hub image must link a SQLite with the WAL-reset fix, FTS5, JSON and extension loading."""

import sqlite3
import unittest


class SQLiteBuildTest(unittest.TestCase):
    def test_version_and_features(self):
        self.assertGreaterEqual(sqlite3.sqlite_version_info, (3, 51, 3))
        con = sqlite3.connect(":memory:")
        con.execute("create virtual table t using fts5(body)")
        self.assertEqual(con.execute("select json_extract('{\"a\":1}', '$.a')").fetchone(), (1,))
        con.enable_load_extension(True)  # sqlite-vec (M4) loads as an extension


if __name__ == "__main__":
    unittest.main()
