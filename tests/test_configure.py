import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


class ConfigureTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='agentbox-config-')
        self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name)
        self.mount=self.home/'projects with spaces'
        self.mount.mkdir()
        self.claude=self.home/'.claude'
        self.codex=self.home/'.codex'
        self.claude.mkdir()
        self.codex.mkdir()
        self.output=self.home/'generated'
        self.config=self.home/'paseo.json'
        self.original={'daemon':{'listen':'127.0.0.1:6767','auth':{'password':'fixture-hash'}},
                       'agents':{'providers':{'existing':{'extends':'claude'}}},
                       'plugins':{'example':{'enabled':True}}}
        self.config.write_text(json.dumps(self.original))

    def run_configure(self,*args):
        return subprocess.run([sys.executable,str(ROOT/'deploy/configure.py'),
            '--mount',str(self.mount),'--output',str(self.output),
            '--claude-config',str(self.claude),'--codex-home',str(self.codex),
            '--paseo-config',str(self.config),*args],capture_output=True,text=True,timeout=10)

    def test_generate_only_leaves_paseo_unchanged_and_profiles_source_safely(self):
        r=self.run_configure()
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(json.loads(self.config.read_text()),self.original)
        providers=json.loads((self.output/'providers.json').read_text())
        self.assertEqual(set(providers),{'claude-box','codex-box'})
        profile=self.output/'profiles/codex.sh'
        r=subprocess.run(['/bin/bash','-c','. "$1"; printf "%s\n" "${MOUNTS[0]}" "$PASEO_PROVIDER"',
                          'test',str(profile)],capture_output=True,text=True,timeout=10)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(r.stdout.splitlines(),[str(self.mount.resolve()),'codex-box'])
        self.assertEqual(profile.stat().st_mode & 0o777,0o600)

    def test_apply_preserves_existing_settings_and_makes_private_backup(self):
        r=self.run_configure('--apply','--with-node','--gitlab-host','gitlab.example.com',
                             '--gitlab-vault-ref','secret/agentbox/gitlab#token')
        self.assertEqual(r.returncode,0,r.stderr)
        config=json.loads(self.config.read_text())
        self.assertEqual(config['plugins'],self.original['plugins'])
        self.assertEqual(config['daemon']['auth'],self.original['daemon']['auth'])
        self.assertTrue(config['daemon']['mcp']['injectIntoAgents'])
        self.assertEqual(len(config['agents']['providers']),7)
        backups=list(self.home.glob('paseo.json.before-agentbox-*'))
        self.assertEqual(len(backups),1)
        self.assertEqual(json.loads(backups[0].read_text()),self.original)
        self.assertEqual(backups[0].stat().st_mode & 0o777,0o600)
        self.assertNotIn('fixture-hash',r.stdout+r.stderr)

    def test_conflicting_custom_provider_does_not_write_profiles(self):
        self.original['agents']['providers']['codex-box']={'command':['/custom/provider']}
        self.config.write_text(json.dumps(self.original))
        r=self.run_configure('--apply')
        self.assertNotEqual(r.returncode,0)
        self.assertIn('refusing to overwrite custom provider',r.stderr)
        self.assertFalse(self.output.exists())
        self.assertEqual(json.loads(self.config.read_text()),self.original)

    def test_legacy_helper_rejects_restricted_provider_without_reenabling_mcp(self):
        self.original['daemon']['mcp']={'injectIntoAgents':False}
        self.original['agents']['providers']['manager-codex']={
            'command':['/opt/agentbox/security/provider.py','--policy','/etc/agentbox/policy.json','--role','manager-codex']}
        self.config.write_text(json.dumps(self.original))
        r=self.run_configure('--apply')
        self.assertNotEqual(r.returncode,0)
        self.assertIn('Restricted/catalog providers detected',r.stderr)
        self.assertEqual(json.loads(self.config.read_text()),self.original)
        self.assertFalse(self.output.exists())

    def test_custom_profile_is_not_overwritten(self):
        profile=self.output/'profiles/claude.sh'
        profile.parent.mkdir(parents=True)
        profile.write_text('# custom profile\n')
        r=self.run_configure('--apply')
        self.assertNotEqual(r.returncode,0)
        self.assertEqual(profile.read_text(),'# custom profile\n')
        self.assertEqual(json.loads(self.config.read_text()),self.original)


if __name__=='__main__':
    unittest.main()
