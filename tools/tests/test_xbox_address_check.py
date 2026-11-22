import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = ROOT / "tools" / "xbox" / "platform" / "address_check.py"
U0, U1, ENTRIES = 0x123456780000, 0x1FFFFF000, 4096
BASE = 1 << 20


def sample_buffers():
    """Build u0/u1 for two threads whose loads, stores and atomics match check()'s model."""
    words = [768, 0xFFFFFE00] + list(range(1, 16))  # signed values 3 and -2 after >> 8
    u0 = struct.pack("<%dI" % len(words), *words)
    w = lambda k: words[k]
    u1 = bytearray(BASE + 192)
    for t in range(2):
        row = [w(t), w(2 * t), w(2 * t + 1), w(3 * t), w(3 * t + 1), w(3 * t + 2),
               w(4 * t), w(4 * t + 1), w(4 * t + 2), w(4 * t + 3), w((t // 64) * 64), 0xFF7FFFFF]
        struct.pack_into("<12I", u1, 64 * t, *row)
    struct.pack_into("<16I", u1, BASE, *([0] * 16))
    struct.pack_into("<16I", u1, BASE + 64, *([0] * 16))
    struct.pack_into("<8f", u1, BASE + 128, 0.0, -2.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    struct.pack_into("<8f", u1, BASE + 160, 3.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    return u0, bytes(u1)


class AddressCheckTest(unittest.TestCase):
    def run_check(self, tmp, u0, u1, threads="2"):
        d = Path(tmp)
        (d / "u0.bin").write_bytes(u0)
        (d / "u1.bin").write_bytes(u1)
        return subprocess.run([sys.executable, "-I", str(SCRIPT), "check", str(d / "u0.bin"),
                               str(d / "u1.bin"), threads], capture_output=True, text=True)

    def test_matching_buffers_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = self.run_check(tmp, *sample_buffers())
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertIn("2 threads: 0 with wrong loads/stores; atomics all as expected", p.stdout)

    def test_corrupt_store_and_atomic_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            u0, u1 = sample_buffers()
            bad = bytearray(u1)
            struct.pack_into("<I", bad, 64, 0xDEADBEEF)
            struct.pack_into("<I", bad, BASE, 5)
            p = self.run_check(tmp, u0, bytes(bad))
            self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
            self.assertIn("1 with wrong loads/stores", p.stdout)
            self.assertIn("add", p.stdout)

    def test_table_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "table.bin"
            p = subprocess.run([sys.executable, "-I", str(SCRIPT), "table", str(path)],
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            data = path.read_bytes()
            self.assertEqual(len(data), 16 + ENTRIES * 16)
            header = struct.unpack_from("<4I", data, 0)
            self.assertEqual(header, (ENTRIES, 0, 0, 0))
            rows = [struct.unpack_from("<4I", data, 16 + 16 * i) for i in range(4)]
            self.assertEqual(rows[0], (0x1000, 0, 0x1000, 1))
            self.assertEqual(rows[1], (U1 & 0xFFFFFFFF, U1 >> 32, 8 << 20, 1))
            self.assertEqual(rows[2], (0, 0x1000000000 >> 32, 0x10000, 0))
            self.assertEqual(rows[3], (U0 & 0xFFFFFFFF, U0 >> 32, 4 << 20, 0))
            self.assertEqual(struct.unpack_from("<4I", data, 16 + 16 * (ENTRIES - 1)),
                             (0xFFFFFFFF, 0xFFFFFFFF, 0, 0))


if __name__ == "__main__":
    unittest.main()
