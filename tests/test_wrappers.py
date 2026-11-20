import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class WrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="agentbox-test-")
        self.addCleanup(self.temp.cleanup)
        self.work = pathlib.Path(self.temp.name)
        self.profiles = self.work / "profiles"
        self.profiles.mkdir()
        self.auth = self.work / "auth"
        self.auth.mkdir()
        self.bin = self.work / "bin"
        self.bin.mkdir()
        self.trace = self.work / "docker.jsonl"
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        AGENTBOX_PROFILE_DIR=str(self.profiles),
                        CLAUDE_CONFIG_DIR=str(self.auth), CODEX_HOME=str(self.auth),
                        AGENTBOX_DAEMON_HOST="host.docker.internal", TRACE=str(self.trace))
        self.executable("docker", """#!/usr/bin/env python3
import json,os,sys
with open(os.environ['TRACE'],'a') as f:
 f.write(json.dumps({'argv':sys.argv[1:],'secret':os.environ.get('TEST_SECRET')})+'\\n')
if sys.argv[1]=='rm':sys.exit(0)
if 'app-server' in sys.argv:
 for line in sys.stdin:print(line,flush=True)
else:
 print(json.dumps({'argv':sys.argv[1:]}))
""")
        self.executable("vault", """#!/usr/bin/env python3
import os,sys
if os.environ.get('VAULT_FAIL'): sys.exit(2)
sys.stdout.write('first line\\nsecond line')
""")

    def executable(self, name, text):
        path = self.bin / name
        path.write_text(text)
        path.chmod(0o755)

    def profile(self, agent="claude", secret=False, privilege="none"):
        text = f'IMAGE=agentbox/base:latest\nAGENT={agent}\nPRIVILEGE={privilege}\n'
        if secret:
            text += 'VAULT_SECRETS=("TEST_SECRET=secret/agentbox/example#token")\n'
        (self.profiles / "test.sh").write_text(text)

    def invoke(self, *args, data="", env=None, shell="/bin/bash"):
        return subprocess.run([shell, str(ROOT / "bin/agentbox-provider"), "--profile", "test", *args],
                              input=data, text=True, capture_output=True,
                              env=self.env if env is None else env, cwd=self.work, timeout=15)

    def test_claude_protocol_and_mcp_headers_survive(self):
        self.profile()
        config = {"mcpServers": {"paseo": {"url": "http://127.0.0.1:6799/mcp/agents?callerAgentId=x",
                                             "headers": {"Authorization": "Bearer test-capability"}}}}
        result = self.invoke("--mcp-config", json.dumps(config), "--input-format", "stream-json")
        self.assertEqual(result.returncode, 0, result.stderr)
        argv = json.loads(result.stdout)["argv"]
        actual = json.loads(argv[argv.index("--mcp-config") + 1])
        server = actual["mcpServers"]["paseo"]
        self.assertEqual(server["url"], "http://host.docker.internal:6799/mcp/agents?callerAgentId=x")
        self.assertEqual(server["headers"], config["mcpServers"]["paseo"]["headers"])
        self.assertNotIn("PASEO_PASSWORD", argv)

    def test_codex_stdin_config_rewritten_but_prompt_untouched(self):
        self.profile("codex")
        message = {"id": 4, "method": "thread/start", "params": {
            "config": {"mcp_servers": {"paseo": {"url": "http://127.0.0.1:6767/mcp/agents"}}},
            "text": "Keep http://127.0.0.1:6767/mcp/agents exactly in this prompt"}}
        result = self.invoke("app-server", data=json.dumps(message) + "\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        actual = json.loads(result.stdout)
        self.assertEqual(actual["params"]["config"]["mcp_servers"]["paseo"]["url"],
                         "http://host.docker.internal:6767/mcp/agents")
        self.assertEqual(actual["params"]["text"], message["params"]["text"])
        events = [json.loads(line) for line in self.trace.read_text().splitlines()]
        self.assertIn("codex", events[0]["argv"])
        self.assertEqual(events[-1]["argv"][:2], ["rm", "-f"])

    def test_multiline_secret_not_in_argv(self):
        self.profile(secret=True)
        result = self.invoke("--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        event = json.loads(self.trace.read_text().splitlines()[0])
        self.assertEqual(event["secret"], "first line\nsecond line")
        self.assertIn("TEST_SECRET", event["argv"])
        self.assertNotIn("first line", result.stdout + result.stderr)

    def test_version_probe_exits_cleanly_with_stdin_still_open(self):
        self.profile()
        proc=subprocess.Popen(['/bin/bash',str(ROOT/'bin/agentbox-provider'),'--profile','test','--version'],
                              stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              env=self.env,cwd=self.work,text=True)
        try:
            code=proc.wait(timeout=10)
            self.assertEqual(code,0,proc.stderr.read())
            self.assertIn('argv',proc.stdout.read())
        finally:
            proc.stdin.close()
            if proc.poll() is None:proc.kill();proc.wait()
            proc.stdout.close();proc.stderr.close()

    def test_vault_failure_never_starts_docker(self):
        self.profile(secret=True)
        result = self.invoke("--version", env=dict(self.env, VAULT_FAIL="1"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("vault read failed", result.stderr)
        self.assertFalse(self.trace.exists())

    def test_sudo_tier_keeps_supplementary_sudo_group_on_linux(self):
        self.profile(privilege="sudo")
        self.executable("uname", "#!/bin/sh\necho Linux\n")
        result = self.invoke("--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        args = json.loads(result.stdout)["argv"]
        self.assertEqual(args[args.index("--group-add") + 1], "sudo")

    def test_visible_spawn_selects_fixed_provider(self):
        self.profile()
        with (self.profiles / "test.sh").open("a") as f:
            f.write('PASEO_PROVIDER=claude-box\n')
        self.executable("paseo", "#!/usr/bin/env python3\nimport json,sys;print(json.dumps(sys.argv[1:]))\n")
        result = subprocess.run(["/bin/bash",str(ROOT / "bin/agentbox"),"spawn","--detach","test","Read README"],
                                text=True,capture_output=True,env=self.env,cwd=self.work,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        args=json.loads(result.stdout)
        self.assertEqual(args[args.index("--provider")+1],"claude-box")
        self.assertIn("--no-wait",args)


if __name__ == "__main__":
    unittest.main()
