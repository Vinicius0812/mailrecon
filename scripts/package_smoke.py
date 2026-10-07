"""Install a built wheel without dependencies and inspect its entrypoint offline."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile


def main():
    wheels = list(Path('dist').glob('mailrecon-*.whl'))
    if len(wheels) != 1:
        raise SystemExit('Expected exactly one MailRecon wheel')
    wheel = wheels[0].resolve()
    with zipfile.ZipFile(wheel) as archive:
        for module in ['mailrecon/reporting/html.py', 'mailrecon/cli/offline.py', 'mailrecon/benchmark.py']:
            if module not in archive.namelist():
                raise SystemExit('Missing packaged module: ' + module)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        target = root / 'installed'
        env = {**os.environ, 'PYTHON_DOTENV_DISABLED': '1'}
        subprocess.run([sys.executable, '-m', 'pip', 'install', '--no-index', '--no-deps', '--target', str(target), str(wheel)], check=True, env=env)
        code = (
            'import sys, socket; sys.path.insert(0, sys.argv[1]); '
            'import mailrecon.cli.app as cli; from pathlib import Path; '
            'assert Path(cli.__file__).resolve().is_relative_to(Path(sys.argv[1]).resolve()); '
            'from typer.testing import CliRunner; '
            'r=CliRunner().invoke(cli.app, ["sources"]); assert r.exit_code == 0, r.output; '
            'r=CliRunner().invoke(cli.app, ["demo", "--output-dir", "demo"]); assert r.exit_code == 0, r.output; '
            'assert len(list(Path("demo").iterdir())) == 9; '
            'from importlib.metadata import distribution; '
            'assert any(e.name == "mailrecon" and e.value == "mailrecon.main:run" for e in distribution("mailrecon").entry_points); '
            'print("Wheel sources/demo and console entrypoint smoke passed")'
        )
        subprocess.run([sys.executable, '-c', code, str(target)], check=True, cwd=root, env=env)


if __name__ == '__main__':
    main()
