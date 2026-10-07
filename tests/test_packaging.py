"""Packaging checks use synthetic archives, never existing dist artifacts."""

import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tomllib
import zipfile

import pytest
from setuptools._distutils.filelist import FileList

from scripts import package_smoke as smoke


def test_runtime_cli_dependency_contract():
    source = Path(__file__).resolve().parents[1] / 'pyproject.toml'
    project = tomllib.loads(source.read_text(encoding='utf-8'))['project']
    runtime = project['dependencies']
    # Exact policy assertions protect the tested minima and pre-vendoring boundary.
    assert [item for item in runtime if item.split('>')[0].casefold() == 'typer'] == ['typer>=0.25.1,<0.26']
    assert [item for item in runtime if item.split('>')[0].casefold() == 'click'] == ['click>=8.3.3,<8.4']
    assert not any(item.casefold().startswith(('typer', 'click'))
                   for item in project['optional-dependencies']['dev'])


def test_generated_core_metadata_declares_runtime_cli_contract():
    from email.parser import Parser
    from setuptools import Distribution
    distribution = Distribution({'name': 'mailrecon', 'version': '0.1.0'})
    distribution.parse_config_files(filenames=[str(Path(__file__).resolve().parents[1] / 'pyproject.toml')])
    output = io.StringIO()
    distribution.metadata.write_pkg_file(output)
    metadata = Parser().parsestr(output.getvalue())
    requirements = metadata.get_all('Requires-Dist', [])
    assert any(item.startswith('typer') and '>=0.25.1' in item and '<0.26' in item for item in requirements)
    assert any(item.startswith('click') and '>=8.3.3' in item and '<8.4' in item for item in requirements)
    assert all('extra ==' not in item for item in requirements if item.startswith(('typer', 'click')))


def fake_archives(tmp_path, wheel_extra=(), sdist_extra=()):
    wheel = tmp_path / 'mailrecon-0.1.0-py3-none-any.whl'
    sdist = tmp_path / 'mailrecon-0.1.0.tar.gz'
    with zipfile.ZipFile(wheel, 'w') as archive:
        for name in sorted(smoke.WHEEL_REQUIRED):
            archive.writestr(name, '')
        for entry in wheel_extra:
            archive.writestr(entry, '')
    with tarfile.open(sdist, 'w:gz') as archive:
        for name in sorted(smoke.SDIST_REQUIRED):
            entry = tarfile.TarInfo('mailrecon-0.1.0/' + name)
            archive.addfile(entry, io.BytesIO(b''))
        for entry in sdist_extra:
            archive.addfile(entry)
    return wheel, sdist


def test_manifest_includes_docs_scripts_and_excludes_local_data():
    manifest = Path(__file__).resolve().parents[1] / 'MANIFEST.in'
    defaults = ['README.md', 'pyproject.toml', 'src/mailrecon/main.py', 'tests/test_cli.py']
    extras = ['READMEeng.md', '.env.example', 'scripts/package_smoke.py',
              'scripts/run_offline_tests.py', 'scripts/future.py', 'docs/guide.md']
    private = ['.env', '.env.local', 'reports/real.json', '.mailrecon-temp/state.json',
               '.venv/lib.py', 'venv/lib.py', '.git/config', '.aws/credentials',
               '.ssh/id_rsa', '.agents/config', '.codex/config', 'src/private.key',
               'src/__pycache__/module.pyc']
    file_list = FileList()
    native = lambda name: name.replace('/', os.sep)
    file_list.set_allfiles([native(name) for name in defaults + extras + private])
    file_list.files = [native(name) for name in defaults + private]
    for line in manifest.read_text(encoding='utf-8').splitlines():
        file_list.process_template_line(line)
    assert set(file_list.files) == {native(name) for name in defaults + extras}


def test_valid_fake_archives(tmp_path):
    smoke.validate_archives(*fake_archives(tmp_path))


@pytest.mark.parametrize('name', [
    '../escape', '/absolute', 'C:/absolute', 'dir\\escape', 'dir/../escape',
    'dir//file', './file', 'file:stream', 'file\x00name', 'file\nname',
    'dir/file.', 'dir/file ', 'dir/NUL.txt', '%2e%2e/escape', '',
    'dir/file?', 'dir/file*', 'dir/file|', 'dir/<file>', 'dir/"file',
])
def test_unsafe_names(name):
    with pytest.raises(ValueError, match='Unsafe'):
        smoke.check_package_members([(name, True)], set())


@pytest.mark.parametrize('name', [
    '.env', '.env.local', 'nested/.env.example', '.ENV', 'reports/real.json',
    'nested/.mailrecon-temp/state.json', '.venv/lib.py', '.git/config',
    '.aws/credentials', '.ssh/id_rsa', 'nested/credentials.json', 'secrets.json',
    'state/data.json', 'private.pem', 'private.key', 'module.pyc',
    'last-investigation-refinement.json', 'nested/credentials.toml',
    'startup.pth', 'sitecustomize.py', 'usercustomize.py',
])
@pytest.mark.parametrize('sdist', [False, True])
def test_sensitive_members(name, sdist):
    root = 'mailrecon-0.1.0' if sdist else None
    member = root + '/' + name if root else name
    with pytest.raises(ValueError, match='Sensitive'):
        smoke.check_package_members([(member, True)], set(), root)


def test_env_example_only_at_sdist_root():
    smoke.check_package_members([('pkg/.env.example', True)], {'.env.example'}, 'pkg')
    with pytest.raises(ValueError, match='Sensitive'):
        smoke.check_package_members([('.env.example', True)], set())


@pytest.mark.parametrize('members, root, message', [
    ([('pkg/file', True), ('pkg/FILE', True)], 'pkg', 'Duplicate'),
    ([('other/file', True)], 'pkg', 'root'),
    ([('pkg/required', False)], 'pkg', 'Missing'),
])
def test_member_collisions_roots_and_missing(members, root, message):
    with pytest.raises(ValueError, match=message):
        smoke.check_package_members(members, {'required'}, root)


@pytest.mark.parametrize('kind', [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE])
def test_sdist_rejects_special_members_without_extraction(tmp_path, monkeypatch, kind):
    entry = tarfile.TarInfo('mailrecon-0.1.0/unsafe')
    entry.type = kind
    entry.linkname = '../../escape'
    archives = fake_archives(tmp_path, sdist_extra=[entry])
    monkeypatch.setattr(tarfile.TarFile, 'extractall', lambda *a, **k: pytest.fail('Extraction'))
    monkeypatch.setattr(tarfile.TarFile, 'extract', lambda *a, **k: pytest.fail('Extraction'))
    with pytest.raises(ValueError, match='member type'):
        smoke.validate_archives(*archives)


def test_wheel_rejects_symlink(tmp_path):
    entry = zipfile.ZipInfo('mailrecon/link')
    entry.create_system = 3
    entry.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(ValueError, match='member type'):
        smoke.validate_archives(*fake_archives(tmp_path, wheel_extra=[entry]))


@pytest.mark.parametrize('name', ['../escape', 'mailrecon/.env', 'mailrecon/reports/real.json'])
def test_fake_archive_bad_names(tmp_path, name):
    with pytest.raises(ValueError):
        smoke.validate_archives(*fake_archives(tmp_path, wheel_extra=[name]))


def test_required_files_not_directories(tmp_path):
    wheel, sdist = fake_archives(tmp_path)
    with zipfile.ZipFile(wheel, 'w') as archive:
        for name in smoke.WHEEL_REQUIRED:
            archive.writestr(name + '/', '')
    with pytest.raises(ValueError, match='Missing'):
        smoke.validate_archives(wheel, sdist)


@pytest.mark.parametrize('wheel_count, sdist_count', [(0, 0), (1, 0), (0, 1), (2, 1), (1, 2)])
def test_requires_unique_distributions(tmp_path, wheel_count, sdist_count):
    for index in range(wheel_count):
        (tmp_path / f'mailrecon-{index}-py3-none-any.whl').touch()
    for index in range(sdist_count):
        (tmp_path / f'mailrecon-{index}.tar.gz').touch()
    with pytest.raises(ValueError, match='exactly one'):
        smoke.find_distributions(tmp_path)


def test_distribution_discovery(tmp_path):
    archives = fake_archives(tmp_path)
    assert smoke.find_distributions(tmp_path) == archives


def test_console_wrapper_discovery(tmp_path):
    with pytest.raises(ValueError):
        smoke.console_wrapper(tmp_path)
    filename = 'mailrecon.exe' if os.name == 'nt' else 'mailrecon'
    (tmp_path / 'bin').mkdir()
    wrapper = tmp_path / 'bin' / filename
    wrapper.touch()
    assert smoke.console_wrapper(tmp_path) == wrapper
    (tmp_path / 'Scripts').mkdir()
    (tmp_path / 'Scripts' / filename).touch()
    with pytest.raises(ValueError):
        smoke.console_wrapper(tmp_path)


def test_environment_and_guard_confirmation(tmp_path, monkeypatch):
    monkeypatch.setenv('PYTHONPATH', '/untrusted')
    env = smoke.smoke_environment(tmp_path / 'installed', tmp_path / 'guard')
    assert env['PYTHONPATH'].split(os.pathsep) == [str(tmp_path / 'guard'), str(tmp_path / 'installed')]
    assert env['PYTHON_DOTENV_DISABLED'] == env['PIP_NO_INDEX'] == '1'
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, 'unguarded', '')
    monkeypatch.setattr(smoke.subprocess, 'run', run)
    with pytest.raises(ValueError, match='guard did not run'):
        smoke.run_guarded(['wrapper', 'sources'], tmp_path, env)
    assert calls[0][1]['check'] and calls[0][1]['timeout'] == 60


def fake_guard_install(tmp_path):
    target = tmp_path / 'installed'
    package = target / 'mailrecon'
    (package / 'cli').mkdir(parents=True)
    for name in ('__init__.py', 'main.py', 'cli/__init__.py', 'cli/app.py'):
        (package / name).write_text('', encoding='utf-8')
    metadata = target / 'mailrecon-0.1.0.dist-info'
    metadata.mkdir()
    (metadata / 'METADATA').write_text('Name: mailrecon\nVersion: 0.1.0\n', encoding='utf-8')
    (metadata / 'entry_points.txt').write_text(
        '[console_scripts]\nmailrecon = mailrecon.main:run\n', encoding='utf-8')
    guard = tmp_path / 'guard'
    guard.mkdir()
    (guard / 'sitecustomize.py').write_text(smoke.GUARD_SOURCE, encoding='utf-8')
    return smoke.smoke_environment(target, guard)


def test_guard_blocks_network_in_child_before_application(tmp_path):
    env = fake_guard_install(tmp_path)
    code = '''import socket, smtplib, os
assert os.environ['PYTHON_DOTENV_DISABLED'] == '1'
s = socket.socket()
operations = [(s.connect, (('127.0.0.1', 9),)), (s.connect_ex, (('127.0.0.1', 9),)),
              (s.send, (b'x',)), (s.sendall, (b'x',)), (s.sendto, (b'x', ('127.0.0.1', 9))),
              (socket.create_connection, (('127.0.0.1', 9),)),
              (socket.getaddrinfo, ('example.invalid', 9)),
              (socket.gethostbyname, ('example.invalid',)),
              (socket.gethostbyname_ex, ('example.invalid',)),
              (socket.gethostbyaddr, ('127.0.0.1',)),
              (socket.getnameinfo, (('127.0.0.1', 9), 0)),
              (smtplib.SMTP, ()), (smtplib.SMTP_SSL, ())]
try:
    for operation, args in operations:
        try:
            operation(*args)
        except AssertionError as error:
            assert 'Real network is forbidden' in str(error)
        else:
            raise AssertionError('Network guard missing')
finally:
    s.close()
print('All guarded operations rejected')
'''
    result = smoke.run_guarded([sys.executable, '-c', code], tmp_path, env)
    assert 'All guarded operations rejected' in result.stdout


def test_guard_fails_closed_on_wrong_import_origin(tmp_path):
    env = fake_guard_install(tmp_path)
    env['MAILRECON_SMOKE_TARGET'] = str(tmp_path / 'wrong')
    result = subprocess.run([sys.executable, '-c', 'print("APP RAN")'],
                            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 91
    assert 'Import did not come from installed wheel' in result.stderr
    assert 'APP RAN' not in result.stdout


@pytest.mark.parametrize('scenario', ['valid', 'empty-sources', 'missing-demo', 'extra-demo'])
def test_smoke_orchestration_uses_real_wrapper_and_local_install(tmp_path, monkeypatch, scenario):
    calls = []
    wheel = tmp_path / 'mailrecon-0.1.0-py3-none-any.whl'
    wheel.touch()

    def run(command, **kwargs):
        calls.append((command, kwargs))
        root = Path(kwargs['cwd'])
        if command[:3] == [sys.executable, '-m', 'pip']:
            target = Path(command[command.index('--target') + 1])
            (target / 'bin').mkdir(parents=True)
            filename = 'mailrecon.exe' if os.name == 'nt' else 'mailrecon'
            (target / 'bin' / filename).touch()
            assert (root / 'guard' / 'sitecustomize.py').read_text(encoding='utf-8') == smoke.GUARD_SOURCE
            return subprocess.CompletedProcess(command, 0, '', '')
        assert Path(command[0]).parent == root / 'installed' / 'bin'
        if command[1] == 'sources':
            output = '' if scenario == 'empty-sources' else 'Synthetic sources output'
        else:
            assert command[1:] == ['demo', '--output-dir', 'demo']
            (root / 'demo').mkdir()
            names = sorted(f'demo-{kind}.{extension}'
                           for kind in ('recon', 'investigation', 'smtp')
                           for extension in ('json', 'md', 'html'))
            if scenario == 'missing-demo':
                names.pop()
            if scenario == 'extra-demo':
                names.append('unexpected.json')
            for name in names:
                (root / 'demo' / name).touch()
            output = 'Synthetic demo output'
        return subprocess.CompletedProcess(command, 0, smoke.GUARD_MARKER + '\n' + output, '')

    monkeypatch.setattr(smoke.subprocess, 'run', run)
    if scenario == 'valid':
        smoke.smoke_wheel(wheel)
    else:
        with pytest.raises(ValueError, match='Empty sources|Unexpected demo'):
            smoke.smoke_wheel(wheel)
    install_command, install_options = calls[0]
    assert all(flag in install_command for flag in ('--no-index', '--no-deps', '--no-compile'))
    assert install_command[-1] == str(wheel)
    assert install_options['env']['PYTHONPATH'] == ''
    assert install_options['env']['PIP_NO_DEPS'] == '1'
    for command, options in calls[1:]:
        assert options['env']['PYTHON_DOTENV_DISABLED'] == '1'
        assert options['env']['PYTHONPATH'].split(os.pathsep)[0].endswith('guard')
        assert options['check'] and options['capture_output']


def test_sdist_missing_required_file(tmp_path):
    wheel, sdist = fake_archives(tmp_path)
    with tarfile.open(sdist, 'w:gz') as archive:
        for name in smoke.SDIST_REQUIRED - {'READMEeng.md'}:
            archive.addfile(tarfile.TarInfo('mailrecon-0.1.0/' + name))
    with pytest.raises(ValueError, match='READMEeng.md'):
        smoke.validate_archives(wheel, sdist)


def test_main_validates_before_installing(tmp_path, monkeypatch):
    fake_archives(tmp_path)
    monkeypatch.setattr(smoke, 'find_distributions', lambda directory: (
        tmp_path / 'mailrecon-0.1.0-py3-none-any.whl', tmp_path / 'mailrecon-0.1.0.tar.gz'))
    events = []
    monkeypatch.setattr(smoke, 'validate_archives', lambda *args: events.append('validate'))
    monkeypatch.setattr(smoke, 'smoke_wheel', lambda *args: events.append('install'))
    smoke.main()
    assert events == ['validate', 'install']


def test_main_never_installs_invalid_archives(tmp_path, monkeypatch):
    archives = fake_archives(tmp_path, wheel_extra=['../escape'])
    monkeypatch.setattr(smoke, 'find_distributions', lambda directory: archives)
    monkeypatch.setattr(smoke, 'smoke_wheel', lambda *args: pytest.fail('Unsafe wheel installation'))
    with pytest.raises(ValueError, match='Unsafe'):
        smoke.main()
