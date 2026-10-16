import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import warnings
from pathlib import Path
from plistlib import dump as dump_plist, load as load_plist

from setuptools import Command, find_packages, setup
from setuptools.command.build_py import build_py as BuildPy


PROJECT_DIR = Path(__file__).resolve().parent
REQUIREMENTS_PATH = PROJECT_DIR / "requirements.txt"
REQUIRED_APPLICATION_DIRECTORIES = ("utils", "templates", "static")
OPTIONAL_APPLICATION_DIRECTORIES = ("cyberseek",)

warnings.filterwarnings("ignore", category=DeprecationWarning, module=r"setuptools\..*")


def runtime_directory():
    system = platform.system()
    if system == "Windows":
        return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "Cyberseek" / "runtime"
    if system == "Darwin":
        return Path("/Library/Application Support/Cyberseek/runtime")
    return Path("/opt/cyberseek")


def runtime_python():
    if platform.system() == "Windows":
        return runtime_directory() / "venv" / "Scripts" / "python.exe"
    return runtime_directory() / "venv" / "bin" / "python"


def application_directory():
    return runtime_directory() / "application"


def copy_application_files(replace=False):
    destination = application_directory()
    if replace and destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    source_app = PROJECT_DIR / "app.py"
    if not source_app.is_file():
        raise RuntimeError("The Cyberseek source is missing app.py.")
    shutil.copy2(source_app, destination / "app.py")
    for name in REQUIRED_APPLICATION_DIRECTORIES:
        source = PROJECT_DIR / name
        target = destination / name
        if not source.is_dir():
            raise RuntimeError(f"The Cyberseek source is missing the required {name}/ directory.")
        if replace or not target.exists():
            shutil.copytree(source, target, dirs_exist_ok=target.exists())
        else:
            shutil.copytree(source, target, dirs_exist_ok=True)
    for name in OPTIONAL_APPLICATION_DIRECTORIES:
        source = PROJECT_DIR / name
        if not source.is_dir():
            continue
        target = destination / name
        if replace or not target.exists():
            shutil.copytree(source, target, dirs_exist_ok=target.exists())
        else:
            shutil.copytree(source, target, dirs_exist_ok=True)


class BuildCyberseekResources(BuildPy):
    def run(self):
        super().run()
        destination = Path(self.build_lib) / "cyberseek"
        self.copy_tree(str(PROJECT_DIR / "templates"), str(destination / "templates"))
        self.copy_tree(str(PROJECT_DIR / "static"), str(destination / "static"))


class InstallCyberseek(Command):
    description = "Install Cyberseek in its private runtime and start its automatic service"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def _install_private_runtime(self):
        directory = runtime_directory()
        python_path = runtime_python()
        directory.mkdir(parents=True, exist_ok=True)
        if not python_path.exists():
            try:
                subprocess.run([sys.executable, "-m", "venv", str(directory / "venv")], check=True)
            except subprocess.CalledProcessError as error:
                raise RuntimeError("Unable to create Cyberseek's private Python environment. Install the python3-venv package and run the command again.") from error
        pip_path = python_path.with_name("pip.exe" if platform.system() == "Windows" else "pip")
        subprocess.run([str(pip_path), "install", "--disable-pip-version-check", "-r", str(REQUIREMENTS_PATH)], check=True)
        copy_application_files(replace=True)

    def run(self):
        if platform.system() == "Linux" and os.geteuid() != 0:
            raise RuntimeError("Run 'sudo python3 setup.py install' so Cyberseek can create its service account and startup service.")
        self._install_private_runtime()
        service = InstallCyberseekService(self.distribution)
        service.ensure_finalized()
        service.run()


class UpdateCyberseek(Command):
    description = "Update Cyberseek application files while preserving configuration and local data"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        system = platform.system()
        if system == "Linux" and os.geteuid() != 0:
            raise RuntimeError("Run 'sudo python3 setup.py update' to update the Cyberseek service files.")
        if not runtime_python().is_file() or not application_directory().is_dir():
            raise RuntimeError("Cyberseek is not installed. Run 'python3 setup.py install' first.")
        copy_application_files()
        if system == "Windows":
            subprocess.run(["schtasks", "/Run", "/TN", "cyberseek"], check=True)
        elif system == "Darwin":
            subprocess.run(["launchctl", "kickstart", "-k", "system/cyberseek"], check=True)
        else:
            subprocess.run(["systemctl", "restart", "--no-block", "cyberseek"], check=True)
        self.announce("Updated Cyberseek application files and restarted the service. Configuration and local data were preserved.")


class ServiceCommand(Command):
    user_options = [
        ("data-dir=", None, "Directory for Cyberseek data, configuration, uploads, and the SQLite database"),
        ("service-name=", None, "Service name, default: cyberseek"),
        ("service-user=", None, "Optional operating-system account used by the Linux service"),
    ]

    def initialize_options(self):
        self.data_dir = None
        self.service_name = None
        self.service_user = None

    def finalize_options(self):
        system = platform.system()
        default_directory = {
            "Windows": Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "Cyberseek",
            "Darwin": Path("/Library/Application Support/Cyberseek"),
        }.get(system, Path("/var/lib/cyberseek"))
        self.data_dir = Path(self.data_dir or default_directory).expanduser().resolve()
        self.service_name = self.service_name or "cyberseek"
        self.service_user = self.service_user or ("cyberseek" if system == "Linux" else None)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", self.service_name):
            raise ValueError("Service name may contain only letters, numbers, dots, underscores, and hyphens.")

    def announce(self, message, level=2):
        self.distribution.announce(message, level)

    def ensure_data_directory(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "instance").mkdir(exist_ok=True)
        (self.data_dir / "uploads").mkdir(exist_ok=True)
        config_path = self.data_dir / "config.ini"
        if not config_path.exists():
            config_path.write_text(
                "[service]\n"
                "PERMANENT_SESSION_LIFETIME = 10\n"
                "INTERFACE = 127.0.0.1\n"
                "PORT = 3000\n"
                "SESSION_COOKIE_SECURE = False\n"
                "SESSION_COOKIE_HTTPONLY = False\n"
                "SESSION_COOKIE_SAMESITE = Lax\n"
                "WTF_CSRF_SSL_STRICT = False\n"
                "UPLOAD_RETENTION_DAYS = 0\n",
                encoding="utf-8",
            )

    def command(self, arguments):
        subprocess.run(arguments, check=True)


class InstallCyberseekService(ServiceCommand):
    description = "Register Cyberseek for automatic operating-system startup"

    def run(self):
        self.ensure_data_directory()
        system = platform.system()
        if system == "Windows":
            self.install_windows()
        elif system == "Darwin":
            self.install_macos()
        else:
            self.install_linux()

    def install_linux(self):
        if os.geteuid() != 0:
            raise RuntimeError("Administrator privileges are required to install the Cyberseek service.")
        import grp
        import pwd

        try:
            account = pwd.getpwnam(self.service_user)
        except KeyError:
            self.command([
                "useradd",
                "--system",
                "--user-group",
                "--home-dir",
                str(self.data_dir),
                "--create-home",
                "--shell",
                "/usr/sbin/nologin",
                self.service_user,
            ])
            account = pwd.getpwnam(self.service_user)
        group_name = grp.getgrgid(account.pw_gid).gr_name
        for directory, directories, files in os.walk(self.data_dir):
            current = Path(directory)
            os.chown(current, account.pw_uid, account.pw_gid)
            os.chmod(current, 0o750)
            for name in directories:
                target = current / name
                os.chown(target, account.pw_uid, account.pw_gid)
                os.chmod(target, 0o750)
            for name in files:
                target = current / name
                os.chown(target, account.pw_uid, account.pw_gid)
                os.chmod(target, 0o640)
        browser_directory = self.data_dir / ".cache" / "ms-playwright"
        browser_directory.mkdir(parents=True, exist_ok=True)
        browser_environment = os.environ.copy()
        browser_environment["PLAYWRIGHT_BROWSERS_PATH"] = str(browser_directory)
        subprocess.run(
            [str(runtime_python()), "-m", "playwright", "install", "--with-deps", "chromium"],
            check=True,
            env=browser_environment,
        )
        os.chown(browser_directory.parent, account.pw_uid, account.pw_gid)
        for directory, directories, files in os.walk(browser_directory):
            current = Path(directory)
            os.chown(current, account.pw_uid, account.pw_gid)
            for name in directories:
                os.chown(current / name, account.pw_uid, account.pw_gid)
            for name in files:
                os.chown(current / name, account.pw_uid, account.pw_gid)
        unit_path = Path("/etc/systemd/system") / f"{self.service_name}.service"
        command = shlex.join([str(runtime_python()), str(application_directory() / "app.py")])
        unit_path.write_text(
            "[Unit]\n"
            "Description=Cyberseek local analysis service\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            f"WorkingDirectory={self.data_dir}\n"
            f"Environment=CYBERSEEK_HOME={self.data_dir}\n"
            f"Environment=PLAYWRIGHT_BROWSERS_PATH={browser_directory}\n"
            "Environment=PYTHONUNBUFFERED=1\n"
            f"User={self.service_user}\n"
            f"Group={group_name}\n"
            f"ExecStart={command}\n"
            "Restart=on-failure\n"
            "RestartSec=5\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n",
            encoding="utf-8",
        )
        self.command(["systemctl", "daemon-reload"])
        self.command(["systemctl", "enable", "--now", self.service_name])
        self.announce(f"Installed and started {self.service_name}.service as {self.service_user} using {self.data_dir}.")

    def install_windows(self):
        launcher = self.data_dir / "run-cyberseek.cmd"
        launcher.write_text(
            "@echo off\r\n"
            f"set \"CYBERSEEK_HOME={self.data_dir}\"\r\n"
            f"\"{runtime_python()}\" \"{application_directory() / 'app.py'}\"\r\n",
            encoding="utf-8",
        )
        self.command([
            "schtasks",
            "/Create",
            "/F",
            "/TN",
            self.service_name,
            "/SC",
            "ONSTART",
            "/RU",
            "SYSTEM",
            "/RL",
            "HIGHEST",
            "/TR",
            str(launcher),
        ])
        self.command(["schtasks", "/Run", "/TN", self.service_name])
        self.announce(f"Installed and started the Windows startup task {self.service_name} using {self.data_dir}.")

    def install_macos(self):
        plist_path = Path("/Library/LaunchDaemons") / f"{self.service_name}.plist"
        with plist_path.open("wb") as destination:
            dump_plist({
                "Label": self.service_name,
                "ProgramArguments": [str(runtime_python()), str(application_directory() / "app.py")],
                "WorkingDirectory": str(self.data_dir),
                "EnvironmentVariables": {"CYBERSEEK_HOME": str(self.data_dir), "PYTHONUNBUFFERED": "1"},
                "RunAtLoad": True,
                "KeepAlive": True,
            }, destination)
        self.command(["launchctl", "bootstrap", "system", str(plist_path)])
        self.command(["launchctl", "kickstart", "-k", f"system/{self.service_name}"])
        self.announce(f"Installed and started the launchd service {self.service_name} using {self.data_dir}.")


class UninstallCyberseek(Command):
    description = "Remove Cyberseek, its automatic-start service, local data, and managed service account"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def _default_data_directory(self):
        system = platform.system()
        return {
            "Windows": Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "Cyberseek",
            "Darwin": Path("/Library/Application Support/Cyberseek"),
        }.get(system, Path("/var/lib/cyberseek"))

    def _service_data_directory(self, unit_path):
        try:
            for line in unit_path.read_text(encoding="utf-8").splitlines():
                if line.startswith("Environment=CYBERSEEK_HOME="):
                    return Path(line.partition("=")[2].partition("=")[2])
                if line.startswith("WorkingDirectory="):
                    return Path(line.partition("=")[2])
        except OSError:
            pass
        return self._default_data_directory()

    def _remove_service(self):
        system = platform.system()
        if system == "Windows":
            subprocess.run(["schtasks", "/Delete", "/F", "/TN", "cyberseek"], check=False)
            return self._default_data_directory()
        if system == "Darwin":
            plist_path = Path("/Library/LaunchDaemons/cyberseek.plist")
            data_directory = self._default_data_directory()
            if plist_path.exists():
                try:
                    with plist_path.open("rb") as source:
                        data_directory = Path(load_plist(source).get("EnvironmentVariables", {}).get("CYBERSEEK_HOME", data_directory))
                except (OSError, ValueError):
                    pass
                subprocess.run(["launchctl", "bootout", "system", str(plist_path)], check=False)
                plist_path.unlink(missing_ok=True)
            return data_directory
        unit_path = Path("/etc/systemd/system/cyberseek.service")
        data_directory = self._service_data_directory(unit_path) if unit_path.exists() else self._default_data_directory()
        subprocess.run(["systemctl", "disable", "--now", "cyberseek"], check=False)
        unit_path.unlink(missing_ok=True)
        subprocess.run(["systemctl", "daemon-reload"], check=False)
        return data_directory

    def _remove_runtime_data(self, data_directory):
        directory = Path(data_directory).expanduser().resolve()
        if directory in {Path("/"), Path.home()}:
            raise ValueError("Refusing to remove an unsafe Cyberseek data directory.")
        if directory == PROJECT_DIR:
            for name in ("instance", ".env", "config.ini"):
                target = directory / name
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink(missing_ok=True)
            upload_directory = directory / "uploads"
            if upload_directory.is_dir():
                for target in upload_directory.iterdir():
                    if target.name == ".gitkeep":
                        continue
                    if target.is_dir():
                        shutil.rmtree(target)
                    else:
                        target.unlink()
            return
        if directory.exists():
            shutil.rmtree(directory)

    def _remove_linux_service_account(self, data_directory):
        if platform.system() != "Linux" or os.geteuid() != 0:
            return
        import grp
        import pwd

        try:
            account = pwd.getpwnam("cyberseek")
        except KeyError:
            return
        expected_directory = Path(data_directory).expanduser().resolve()
        account_directory = Path(account.pw_dir).expanduser().resolve()
        if account.pw_uid >= 1000 or account_directory != expected_directory:
            return
        group_name = None
        try:
            group = grp.getgrgid(account.pw_gid)
            if group.gr_name == "cyberseek" and not group.gr_mem:
                group_name = group.gr_name
        except KeyError:
            pass
        subprocess.run(["userdel", "cyberseek"], check=False)
        if group_name:
            try:
                grp.getgrnam(group_name)
            except KeyError:
                return
            subprocess.run(["groupdel", group_name], check=False)

    def _remove_private_runtime(self):
        directory = runtime_directory().resolve()
        safe_directories = {
            Path("/opt/cyberseek").resolve(),
            (Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "Cyberseek" / "runtime").resolve(),
            Path("/Library/Application Support/Cyberseek/runtime").resolve(),
        }
        if directory not in safe_directories:
            raise ValueError("Refusing to remove an unsafe Cyberseek runtime directory.")
        if directory.exists():
            shutil.rmtree(directory)

    def run(self):
        if platform.system() == "Linux" and os.geteuid() != 0:
            raise RuntimeError("Run 'sudo python3 setup.py uninstall' to remove the Cyberseek service and its managed account.")
        data_directory = self._remove_service()
        self._remove_runtime_data(data_directory)
        self._remove_linux_service_account(data_directory)
        self._remove_private_runtime()
        self._remove_runtime_data(PROJECT_DIR)
        self.announce("Cyberseek package, automatic-start service, local data, and managed service account were removed.")


setup(
    name="cyberseek",
    version="1.0.0",
    description="Local cybersecurity analysis and monitoring console",
    long_description=(PROJECT_DIR / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    python_requires=">=3.9",
    py_modules=["app"],
    packages=find_packages(include=["utils", "utils.*"]),
    install_requires=REQUIREMENTS_PATH.read_text(encoding="utf-8").splitlines(),
    include_package_data=True,
    package_data={},
    entry_points={"console_scripts": ["cyberseek=app:main"]},
    cmdclass={
        "build_py": BuildCyberseekResources,
        "install": InstallCyberseek,
        "update": UpdateCyberseek,
        "uninstall": UninstallCyberseek,
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
)
