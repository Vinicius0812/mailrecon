"""Validate distributions and run the installed console wrapper without network."""

import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile


WHEEL_REQUIRED = {
    'mailrecon/__init__.py', 'mailrecon/main.py', 'mailrecon/cli/app.py',
    'mailrecon/reporting/html.py', 'mailrecon/cli/offline.py', 'mailrecon/benchmark.py',
}
SDIST_REQUIRED = {
    'README.md', 'READMEeng.md', '.env.example', 'pyproject.toml', 'MANIFEST.in',
    'scripts/package_smoke.py', 'scripts/run_offline_tests.py',
    'docs/RELATORIO-NOTURNO-2026-10-07.md', 'tests/test_readme_examples.py',
    'tests/test_packaging.py', *('src/' + name for name in WHEEL_REQUIRED),
}
FORBIDDEN_PARTS = {
    '.git', '.hg', '.svn', '.aws', '.ssh', '.agents', '.codex', '.venv', 'venv',
    'env', '.tox', '.nox',
    'reports', 'report', 'state', '.mailrecon-temp', '__pycache__',
    'credentials', 'secrets', 'dist', 'build',
}
GUARD_MARKER = 'MailRecon installed-wheel offline guard active'


def checked_name(name):
    """Use portable names; reject traversal and Windows path ambiguities."""
    if not name or any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise ValueError('Unsafe archive member: ' + repr(name))
    if any(char in name for char in '\\:%*?"<>|') or name.startswith('/'):
        raise ValueError('Unsafe archive member: ' + repr(name))
    parts = name.removesuffix('/').split('/')
    if any(part in {'', '.', '..'} or part.endswith((' ', '.')) for part in parts):
        raise ValueError('Unsafe archive member: ' + repr(name))
    for part in parts:
        stem = part.split('.')[0].casefold()
        if stem in {'con', 'prn', 'aux', 'nul', *(f'com{i}' for i in range(1, 10)),
                    *(f'lpt{i}' for i in range(1, 10))}:
            raise ValueError('Unsafe archive member: ' + repr(name))
    return '/'.join(parts)


def check_package_members(members, required, root=None):
    files = set()
    seen = set()
    for name, is_file in members:
        path = checked_name(name)
        key = path.casefold()
        if key in seen:
            raise ValueError('Duplicate archive member: ' + name)
        seen.add(key)
        if root is not None:
            if path == root and not is_file:
                continue
            if not path.startswith(root + '/'):
                raise ValueError('Unexpected sdist root: ' + name)
            path = path[len(root) + 1:]
        parts = path.casefold().split('/')
        if any(part in FORBIDDEN_PARTS for part in parts):
            raise ValueError('Sensitive archive member: ' + name)
        for part in parts:
            if (part == '.env' or part.startswith('.env.')
                    or part.endswith(('.pem', '.key', '.pyc', '.pyo', '.pth'))
                    or part.startswith(('credentials.', 'secrets.'))
                    or part in {'id_rsa', 'id_ed25519', 'last-investigation-refinement.json',
                                'sitecustomize.py', 'usercustomize.py'}):
                if path != '.env.example' or root is None:
                    raise ValueError('Sensitive archive member: ' + name)
        if is_file:
            files.add(path)
    missing = required - files
    if missing:
        raise ValueError('Missing packaged files: ' + ', '.join(sorted(missing)))


def validate_archives(wheel, sdist):
    with zipfile.ZipFile(wheel) as archive:
        members = []
        for entry in archive.infolist():
            mode = entry.external_attr >> 16
            if stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}:
                raise ValueError('Unsafe wheel member type: ' + entry.filename)
            members.append((entry.filename, not entry.is_dir()))
        check_package_members(members, WHEEL_REQUIRED)
    with tarfile.open(sdist, 'r:gz') as archive:
        members = []
        for entry in archive:
            if not (entry.isfile() or entry.isdir()):
                raise ValueError('Unsafe sdist member type: ' + entry.name)
            members.append((entry.name, entry.isfile()))
        check_package_members(members, SDIST_REQUIRED, sdist.name.removesuffix('.tar.gz'))


def find_distributions(directory):
    wheels = list(directory.glob('mailrecon-*.whl'))
    sdists = list(directory.glob('mailrecon-*.tar.gz'))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ValueError('Expected exactly one MailRecon wheel and one sdist')
    return wheels[0].resolve(), sdists[0].resolve()


# sitecustomize runs inside the real pip-generated wrapper before project imports.
# Fail closed: Python normally only warns when sitecustomize raises an exception.
GUARD_SOURCE = '''import os
import smtplib
import socket
import sys
from pathlib import Path

def forbidden(*args, **kwargs):
    raise AssertionError("Real network is forbidden in package smoke")

try:
    os.environ["PYTHON_DOTENV_DISABLED"] = "1"
    for name in ("connect", "connect_ex", "send", "sendall", "sendto"):
        setattr(socket.socket, name, forbidden)
    for name in ("create_connection", "getaddrinfo", "gethostbyname",
                 "gethostbyname_ex", "gethostbyaddr", "getnameinfo"):
        setattr(socket, name, forbidden)
    smtplib.SMTP = forbidden
    smtplib.SMTP_SSL = forbidden
    target = Path(os.environ["MAILRECON_SMOKE_TARGET"]).resolve()
    import mailrecon.cli.app as cli
    import mailrecon.main as main
    from importlib.metadata import distribution
    for module in (cli, main):
        if not Path(module.__file__).resolve().is_relative_to(target):
            raise AssertionError("Import did not come from installed wheel")
    dist = distribution("mailrecon")
    if not Path(dist.locate_file("")).resolve().is_relative_to(target):
        raise AssertionError("Metadata did not come from installed wheel")
    if not any(e.group == "console_scripts" and e.name == "mailrecon"
               and e.value == "mailrecon.main:run" for e in dist.entry_points):
        raise AssertionError("Missing console entrypoint")
    print("MailRecon installed-wheel offline guard active", flush=True)
except BaseException as error:
    print("Package smoke startup failed: " + repr(error), file=sys.stderr, flush=True)
    os._exit(91)
'''


def smoke_environment(target, guard):
    return {
        **os.environ,
        'PYTHON_DOTENV_DISABLED': '1',
        'PYTHONPATH': os.pathsep.join([str(guard), str(target)]),
        'PYTHONNOUSERSITE': '1',
        'MAILRECON_SMOKE_TARGET': str(target),
        'PIP_NO_INDEX': '1',
        'PIP_DISABLE_PIP_VERSION_CHECK': '1',
        'PIP_CONFIG_FILE': os.devnull,
    }


def console_wrapper(target):
    filename = 'mailrecon.exe' if os.name == 'nt' else 'mailrecon'
    candidates = [target / directory / filename for directory in ('bin', 'Scripts')]
    found = [path for path in candidates if path.is_file()]
    if len(found) != 1:
        raise ValueError('Expected exactly one installed console wrapper')
    return found[0]


def run_guarded(command, root, env):
    result = subprocess.run(command, check=True, cwd=root, env=env,
                            capture_output=True, text=True, timeout=60)
    if GUARD_MARKER not in result.stdout.splitlines():
        raise ValueError('Offline startup guard did not run')
    return result


def smoke_wheel(wheel):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        target = root / 'installed'
        guard = root / 'guard'
        guard.mkdir()
        (guard / 'sitecustomize.py').write_text(GUARD_SOURCE, encoding='utf-8')
        env = smoke_environment(target, guard)
        # pip has only a local wheel as input; startup imports apply to the wrapper.
        install_env = {**env, 'PYTHONPATH': '', 'PIP_NO_DEPS': '1'}
        subprocess.run([sys.executable, '-m', 'pip', 'install', '--no-index',
                        '--no-deps', '--no-compile', '--target', str(target), str(wheel)],
                       check=True, cwd=root, env=install_env, timeout=60)
        wrapper = console_wrapper(target)
        sources = run_guarded([str(wrapper), 'sources'], root, env)
        if not sources.stdout.replace(GUARD_MARKER, '').strip():
            raise ValueError('Empty sources output')
        run_guarded([str(wrapper), 'demo', '--output-dir', 'demo'], root, env)
        expected = {f'demo-{kind}.{extension}' for kind in ('recon', 'investigation', 'smtp')
                    for extension in ('json', 'md', 'html')}
        if {path.name for path in (root / 'demo').iterdir()} != expected:
            raise ValueError('Unexpected demo artifacts')
        print('Wheel real console sources/demo, import origin and offline guard smoke passed')


def main():
    wheel, sdist = find_distributions(Path('dist'))
    validate_archives(wheel, sdist)
    print('Wheel/sdist required files and unsafe/sensitive member checks passed')
    smoke_wheel(wheel)


if __name__ == '__main__':
    main()
