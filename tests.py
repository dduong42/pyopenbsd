import os
import signal
import tempfile
import unittest

import openbsd


class ProcessTestCase(unittest.TestCase):
    """This class adds helper methods for PledgeTestCase and UnveilTestCase"""

    def assert_exit_status_equals(self, status):
        _, exit_status_indication = os.wait()
        signal_number = exit_status_indication & 0x4f
        self.assertEqual(signal_number, 0)
        has_core_dump = exit_status_indication & 0x80 == 0x80
        self.assertFalse(has_core_dump)
        exit_status = (exit_status_indication >> 8) & 0xff
        self.assertEqual(exit_status, status)


class PledgeTestCase(ProcessTestCase):
    def assert_process_gets_killed(self):
        _, exit_status_indication = os.wait()
        # To get the signal number, we need the 7 first bits.
        # The 8th bit is set when a core dump is generated
        signal_number = exit_status_indication & 0x4f
        self.assertEqual(signal.SIGABRT, signal_number)
        has_core_dump = exit_status_indication & 0x80 == 0x80
        self.assertTrue(has_core_dump)

    def test_process_gets_killed(self):
        """Ensures that a process gets killed when it violates promises it sent
        to `pledge`"""

        pid = os.fork()
        if pid:
            self.assert_process_gets_killed()
        else:
            openbsd.pledge('stdio', '')
            # Not gonna happen
            os.fork()

    def test_process_gets_killed_exec(self):
        """Test the case where the process gets killed because of the condition
        in `execpromises`"""

        pid = os.fork()
        if pid:
            self.assert_process_gets_killed()
        else:
            openbsd.pledge(None, 'stdio')
            os.execlp('ps', 'ps')

    def test_process_doesnt_get_killed(self):
        """Ensure that a process doesn't get killed when keeping its
        promises."""

        pid = os.fork()
        if pid:
            self.assert_exit_status_equals(42)
        else:
            openbsd.pledge('stdio', '')
            os._exit(42)

    def test_pledge_none_has_no_effect(self):
        """Ensure that pledge(None, None) has no effect."""

        pid = os.fork()
        if pid:
            self.assert_exit_status_equals(42)
        else:
            openbsd.pledge(None, None)
            os._exit(42)

    def test_pledge_none_has_no_effect_exec(self):
        """Test pledge(None, None) but on a child process that calls `execve`"""

        pid = os.fork()
        if pid:
            self.assert_exit_status_equals(1)
        else:
            openbsd.pledge(None, None)
            os.execlp('test', 'test', '')


class UnveilTestCase(ProcessTestCase):
    def test_unveil_removes_access(self):
        """Ensure that we cannot access path that we didn't authorize"""

        pid = os.fork()
        if pid:
            self.assert_exit_status_equals(0)
        else:
            openbsd.unveil('/bin', 'r')
            try:
                f = open('/etc/hosts')
            except IOError:
                os._exit(0)
            else:
                f.close()
                os._exit(1)

    def test_unveil_can_read(self):
        """Test that we can read an authorized file"""

        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(b'hello')
            tmp.flush()

            pid = os.fork()
            if pid:
                self.assert_exit_status_equals(0)
            else:
                openbsd.unveil(tmp.name, 'r')
                with open(tmp.name) as f:
                    content = f.read()
                    os._exit(0 if content == 'hello' else 1)

    def test_unveil_cannot_write(self):
        """Test that we cannot write when only read permission is given"""

        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(b'hello')
            tmp.flush()

            pid = os.fork()
            if pid:
                self.assert_exit_status_equals(0)
            else:
                openbsd.unveil(tmp.name, 'r')
                try:
                    f = open(tmp.name, 'w')
                except IOError:
                    os._exit(0)
                else:
                    f.close()
                    os._exit(1)

    def test_unveil_can_write(self):
        """Test that we can write when only write permission is given"""

        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(b'hello')
            tmp.flush()

            pid = os.fork()
            if pid:
                self.assert_exit_status_equals(0)
                tmp.seek(0)
                self.assertEqual(tmp.read(), b'changed')
            else:
                openbsd.unveil(tmp.name, 'w')
                # Cannot use open(tmp.name, 'w') because it needs the 'c'
                # permission too.
                fd = os.open(tmp.name, os.O_WRONLY)
                os.write(fd, b'changed')
                os._exit(0)
