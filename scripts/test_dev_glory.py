"""Registry-first builds and debounced source watching for both hosts."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch
import dev_glory as dev

class DeveloperWorkflowTests(unittest.TestCase):
    def test_check_is_read_only_when_registry_is_stale(self):
        with patch.object(dev,'parse_args',return_value=Mock(check=True)),patch.object(dev,'build_environment',return_value={}),patch.object(dev.registry,'require_registry_alignment',side_effect=RuntimeError('stale')),patch.object(dev.registry,'ensure_registry_alignment') as repair,patch.object(dev.registry,'cargo_metadata') as metadata:
            self.assertEqual(dev.main(),1)
        repair.assert_not_called();metadata.assert_not_called()

    def test_native_start_repairs_before_any_build_or_launch(self):
        order=[]
        def repair():order.append('repair')
        def build(command,**options):
            self.assertEqual(order,['repair','metadata']);order.append('build')
            self.assertEqual(command,['cargo','build','--locked','--features','desktop','--bin','inkson'])
        def launch(command,**options):
            self.assertEqual(order,['repair','metadata','build']);order.append('launch')
            return Mock(poll=Mock(return_value=0),returncode=0)
        def metadata():
            order.append('metadata');return {'target_directory':'D:/BuildCache/inkson-glory/target','packages':[]}
        with patch.object(dev,'parse_args',return_value=Mock(check=False,platform='desktop',port=8080)),patch.object(dev,'build_environment',return_value={}),patch.object(dev.registry,'ensure_registry_alignment',side_effect=repair),patch.object(dev.registry,'cargo_metadata',side_effect=metadata),patch.object(dev.registry,'local_dependency_roots',return_value=[]),patch.object(dev.threading,'Thread'),patch.object(dev.subprocess,'run',side_effect=build),patch.object(dev.subprocess,'Popen',side_effect=launch):
            self.assertEqual(dev.main(),0)
        self.assertEqual(order,['repair','metadata','build','launch'])

    def test_repair_requests_one_rebuild_and_failure_withholds_it(self):
        for failure in (None,RuntimeError('generation failed')):
            with self.subTest(failure=failure):
                stop=Mock();stop.wait.side_effect=[False,False,False,True]
                before={Path('spec.json'):(1,1)};changed={Path('spec.json'):(2,1)};repaired={**changed,Path('generated.rs'):(3,1)}
                snapshots=[before,changed,changed,repaired,repaired] if not failure else [before,changed,changed,changed]
                rebuild=Mock()
                with patch.object(dev.registry,'watched_files',side_effect=snapshots),patch.object(dev.time,'monotonic',side_effect=[0.0,3.0]),patch.object(dev.registry,'ensure_registry_alignment',side_effect=failure) as repair:
                    dev.dependency_watch_loop([],set(),stop,rebuild)
                repair.assert_called_once()
                if failure:rebuild.assert_not_called()
                else:rebuild.assert_called_once()

    def test_watch_includes_css_javascript_and_manifest_but_excludes_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);cache=root/'real-build-cache';cache.mkdir();(cache/'build.rs').write_text('generated')
            (root/'theme.css').write_text('body{}');(root/'host.js').write_text('export {}');(root/'styles.list').write_text('theme.css')
            evidence=root/'artifacts';evidence.mkdir();(evidence/'capture.json').write_text('{}')
            with patch.object(dev.registry,'SPEC_REGISTRY',root/'missing.json'):
                watched=dev.registry.watched_files([root],{cache})
            self.assertIn(root/'theme.css',watched);self.assertIn(root/'host.js',watched);self.assertIn(root/'styles.list',watched)
            self.assertNotIn(cache/'build.rs',watched);self.assertNotIn(evidence/'capture.json',watched)
if __name__=='__main__':unittest.main()
