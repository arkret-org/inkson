"""Pure mocks for Glory's existing build, HTTP and native-child lifecycle."""
from contextlib import ExitStack
from pathlib import Path
import subprocess
import tempfile
import threading
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
        def build(owner,stop,command,**options):
            self.assertEqual(order,['repair','metadata']);order.append('build')
            self.assertEqual(command,['cargo','build','--locked','--features','desktop','--bin','inkson'])
            return True
        def launch(command,**options):
            self.assertEqual(order,['repair','metadata','build']);order.append('launch')
            return Mock(poll=Mock(return_value=0),returncode=0)
        def metadata():
            order.append('metadata');return {'target_directory':'C:/workspace/inkson-output','packages':[]}
        thread=Mock();thread.is_alive.return_value=False
        with patch.object(dev,'parse_args',return_value=Mock(check=False,platform='desktop',port=8080)),patch.object(dev,'build_environment',return_value={}),patch.object(dev.registry,'ensure_registry_alignment',side_effect=repair),patch.object(dev.registry,'cargo_metadata',side_effect=metadata),patch.object(dev.registry,'local_dependency_roots',return_value=[]),patch.object(dev.registry,'watched_files',return_value={}),patch.object(dev.threading,'Thread',return_value=thread),patch.object(dev,'run_owned_build',side_effect=build),patch.object(dev.subprocess,'Popen',side_effect=launch):
            self.assertEqual(dev.main(),0)
        self.assertEqual(order,['repair','metadata','build','launch'])

    def test_repair_requests_one_rebuild_and_failure_withholds_it(self):
        for failure in (None,RuntimeError('generation failed')):
            with self.subTest(failure=failure):
                stop=Mock();stop.wait.side_effect=[False,False,False,True];stop.is_set.return_value=False
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
            for name in ('theme.css','host.js','styles.list'):(root/name).write_text('source')
            evidence=root/'artifacts';evidence.mkdir();(evidence/'capture.json').write_text('{}')
            # Git's exact source inventory excludes the ignored proof file.
            listed=b'theme.css\0host.js\0styles.list\0real-build-cache/build.rs\0'
            with patch.object(dev.registry,'SPEC_REGISTRY',root/'missing.json'),patch.object(dev.registry.subprocess,'run',return_value=Mock(stdout=listed)):
                watched=dev.registry.watched_files([root],{cache})
            self.assertEqual(set(watched),{root/'theme.css',root/'host.js',root/'styles.list'})


class LifecycleTests(unittest.TestCase):
    def test_poll_slot_holds_lock_and_never_exports_old_popen(self):
        owner=dev.OwnedProcesses(threading.Event());child=Mock()
        def poll():
            self.assertTrue(owner.lock.locked())
            return 0
        child.poll.side_effect=poll
        with patch.object(dev.subprocess,'Popen',return_value=child):owner.start('desktop',['owned'])
        self.assertEqual(owner.poll_slot('desktop'),0)
        self.assertIsNone(owner.poll_slot('not-present'))

    def test_main_ignores_old_desktop_exit_during_replacement_build(self):
        old=Mock();old.returncode=None;old.poll.side_effect=lambda:old.returncode
        old.terminate.side_effect=lambda:setattr(old,'returncode',-15)
        old.wait.side_effect=lambda timeout:old.returncode
        build=Mock();build.returncode=None;build.poll.side_effect=lambda:build.returncode
        build.terminate.side_effect=lambda:setattr(build,'returncode',-15)
        build.wait.side_effect=lambda timeout:build.returncode
        replacement=Mock();replacement.poll.return_value=0;replacement.returncode=0;replacement.wait.return_value=0
        worker=Mock();worker.is_alive.return_value=False
        original=dev.OwnedProcesses.poll_slot;observed=[]
        def interleave(owner,name):
            if not observed:
                owner.close('desktop');owner.start('build',['owned-replacement-build'])
                value=original(owner,name)
                self.assertIsNone(value);self.assertEqual(old.returncode,-15)
                self.assertEqual(build.terminate.call_count,0)
                observed.append('old desktop is gone; replacement build remains active')
                return value
            self.assertEqual(build.terminate.call_count,0)
            observed.append('main continued instead of treating old -15 as user exit')
            owner.close('build');owner.start('desktop',['owned-new-desktop'])
            return original(owner,name)
        with ExitStack() as stack:
            for obj,name,value in [(dev,'parse_args',Mock(check=False,platform='desktop',port=8080)),(dev,'build_environment',{}),(dev.registry,'cargo_metadata',{'target_directory':'C:/workspace/inkson-output','packages':[]}),(dev.registry,'local_dependency_roots',[]),(dev.registry,'watched_files',{}),(dev,'run_owned_build',True),(dev.threading,'Thread',worker)]:stack.enter_context(patch.object(obj,name,return_value=value))
            stack.enter_context(patch.object(dev.registry,'ensure_registry_alignment'))
            stack.enter_context(patch.object(dev.subprocess,'Popen',side_effect=[old,build,replacement]))
            stack.enter_context(patch.object(dev.OwnedProcesses,'poll_slot',interleave))
            self.assertEqual(dev.main(),0)
        self.assertEqual(len(observed),2)
        replacement.terminate.assert_not_called()

    def test_owned_child_bounded_cleanup(self):
        child=Mock();child.poll.return_value=None;child.wait.side_effect=[subprocess.TimeoutExpired('owned',3),-9]
        self.assertEqual(dev.stop_owned_process(child),-9)
        child.terminate.assert_called_once();child.kill.assert_called_once()
        self.assertEqual([c.kwargs for c in child.wait.call_args_list],[{'timeout':3},{'timeout':3}])

    def test_no_owned_launch_after_stop(self):
        stop=threading.Event();owner=dev.OwnedProcesses(stop);stop.set()
        with patch.object(dev.subprocess,'Popen') as create:self.assertIsNone(owner.start('desktop',['owned']))
        create.assert_not_called()

    def test_popen_failure_registers_no_unowned_process(self):
        owner=dev.OwnedProcesses(threading.Event())
        with patch.object(dev.subprocess,'Popen',side_effect=OSError('mock')):
            with self.assertRaises(OSError):owner.start('build',['owned'])
        self.assertEqual(owner.processes,{})

    def test_owned_build_cancellation_reaps_only_its_process(self):
        stop=threading.Event();owner=dev.OwnedProcesses(stop);child=Mock();child.poll.return_value=None
        def wait(timeout):
            if timeout==0.5:stop.set();raise subprocess.TimeoutExpired('build',timeout)
            child.poll.return_value=-15;return -15
        child.wait.side_effect=wait
        with patch.object(dev.subprocess,'Popen',return_value=child):
            self.assertFalse(dev.run_owned_build(owner,stop,['owned-build'],cwd=Path('D:/owned')))
        child.terminate.assert_called_once();child.kill.assert_not_called();self.assertEqual(owner.processes,{})

    def test_owned_build_nonzero_keeps_original_check_semantics(self):
        child=Mock();child.wait.return_value=7;child.poll.return_value=7
        owner=dev.OwnedProcesses(threading.Event())
        with patch.object(dev.subprocess,'Popen',return_value=child):
            with self.assertRaises(subprocess.CalledProcessError) as caught:dev.run_owned_build(owner,owner.stop,['owned-build'])
        self.assertEqual(caught.exception.returncode,7);self.assertEqual(caught.exception.cmd,['owned-build'])
        child.terminate.assert_not_called();self.assertEqual(owner.processes,{})

    def test_scan_failures_at_all_phases_escape_with_no_rebuild(self):
        for scans in ([RuntimeError('listing')],[{},RuntimeError('listing')],[{}, {'changed':1},{'changed':1},RuntimeError('listing')]):
            stop=Mock();stop.wait.return_value=False;stop.is_set.return_value=False;build=Mock()
            with patch.object(dev.registry,'watched_files',side_effect=scans),patch.object(dev.registry,'ensure_registry_alignment'),patch.object(dev.time,'monotonic',side_effect=[0.,3.]):
                with self.assertRaisesRegex(RuntimeError,'listing'):dev.dependency_watch_loop([],set(),stop,build)
            build.assert_not_called()

    def launcher(self,mode,platform='desktop'):
        callbacks=[];thread=Mock();thread.is_alive.return_value=mode=='alive'
        child=Mock();child.poll.return_value=0;child.returncode=0;child.wait.return_value=0
        server=Mock()
        def make_thread(**options):
            callback=options['target'];callbacks.append(callback)
            if mode in ('before','failure'):thread.start.side_effect=callback
            if mode in ('join-error','interrupt-join-error'):thread.join.side_effect=lambda **_:callback()
            return thread
        def request():
            if mode=='web-failure':callbacks[0]()
            else:raise KeyboardInterrupt()
        server.handle_request.side_effect=request
        if mode=='interrupt-join-error':child.poll.side_effect=[KeyboardInterrupt(),0]
        with ExitStack() as stack:
            for obj,name,value in [(dev,'parse_args',Mock(check=False,platform=platform,port=8080)),(dev,'build_environment',{}),(dev.registry,'cargo_metadata',{'target_directory':'C:/workspace/inkson-output','packages':[]}),(dev.registry,'local_dependency_roots',[])]:stack.enter_context(patch.object(obj,name,return_value=value))
            stack.enter_context(patch.object(dev.registry,'ensure_registry_alignment'))
            scan=stack.enter_context(patch.object(dev.registry,'watched_files',side_effect=(subprocess.TimeoutExpired('git',2) if mode=='initial-scan' else None),return_value={}))
            build=stack.enter_context(patch.object(dev,'run_owned_build',return_value=True))
            stack.enter_context(patch.object(dev.threading,'Thread',side_effect=make_thread))
            stack.enter_context(patch.object(dev,'dependency_watch_loop',side_effect=RuntimeError('listing unavailable')))
            launch=stack.enter_context(patch.object(dev.subprocess,'Popen',side_effect=(OSError('mock launch') if mode=='launch-error' else None),return_value=child))
            make_server=stack.enter_context(patch.object(dev,'ThreadingHTTPServer',side_effect=(OSError('bind failed') if mode=='server-error' else None),return_value=server))
            result=dev.main()
        return result,thread,child,server,launch,build,make_server

    def test_initial_scan_failure_never_builds_or_launches(self):
        result,thread,child,server,launch,build,_=self.launcher('initial-scan')
        self.assertEqual(result,1);build.assert_not_called();launch.assert_not_called();thread.start.assert_not_called()

    def test_ordinary_native_exit_zero_and_join(self):
        result,thread,child,*_=self.launcher('normal')
        self.assertEqual(result,0);thread.join.assert_called_once_with(timeout=3);child.terminate.assert_not_called()

    def test_late_join_failure_overrides_zero(self):
        self.assertEqual(self.launcher('join-error')[0],1)

    def test_interrupt_then_late_join_failure_overrides_zero(self):
        self.assertEqual(self.launcher('interrupt-join-error')[0],1)

    def test_still_alive_after_join_is_not_success(self):
        self.assertEqual(self.launcher('alive')[0],1)

    def test_watcher_failure_before_web_bind(self):
        result,thread,child,server,launch,build,make_server=self.launcher('before','web')
        self.assertEqual(result,1);make_server.assert_not_called();launch.assert_not_called();thread.join.assert_called_once_with(timeout=3)

    def test_web_request_loop_observes_failure_and_closes_server(self):
        result,thread,child,server,*_=self.launcher('web-failure','web')
        self.assertEqual(result,1);self.assertEqual(server.timeout,0.5);server.handle_request.assert_called_once();server.server_close.assert_called_once()

    def test_web_keyboard_interrupt_closes_server(self):
        result,thread,child,server,*_=self.launcher('normal','web')
        self.assertEqual(result,0);server.server_close.assert_called_once();thread.join.assert_called_once_with(timeout=3)

    def test_server_construction_failure_stops_watcher(self):
        result,thread,*_=self.launcher('server-error','web')
        self.assertEqual(result,1);thread.join.assert_called_once_with(timeout=3)

    def test_desktop_launch_failure_does_not_start_or_leak_watcher(self):
        result,thread,*_=self.launcher('launch-error')
        self.assertEqual(result,1);thread.start.assert_not_called()


if __name__=='__main__':unittest.main()
