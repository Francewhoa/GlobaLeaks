# -*- coding: utf-8
import os

from globaleaks.utils.securetempfile import SecureTemporaryFileWrite, SecureTemporaryFileRead
from globaleaks.settings import Settings
from globaleaks.tests import helpers


class TestSecureTemporaryFileReads(helpers.TestGL):
    def test_temporary_file(self):
        a = SecureTemporaryFileWrite(Settings.tmp_upload_path, Settings.tmp_upload_path)
        antani = "0123456789"
        for _ in range(1000):
            a.write(antani)
        a.finalize()
        a.close()

        b = SecureTemporaryFileRead(a.filepath, Settings.tmp_upload_path)
        for x in range(1000):
            self.assertTrue(antani == b.read(10))

        b.close()
