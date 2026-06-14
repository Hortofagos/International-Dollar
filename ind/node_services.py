"""Process and environment helpers for the desktop node controls."""

import os
import platform
import subprocess
import sys
from pathlib import Path


LOCAL_OPERATOR_URL = 'http://127.0.0.1:8890'
LOCAL_OPERATOR_MIRROR_DIR = 'files/transparency_roots'
LOCAL_OPERATOR_ROOT_INTERVAL_SECONDS = 2
LOCAL_OPERATOR_SUBMISSION_VERIFY_TIMEOUT_SECONDS = 8
LOCAL_OPERATOR_ENV_KEYS = (
    'IND_SUBMIT_TO_TRANSPARENCY_LOG',
    'IND_LOG_OPERATOR_URL',
    'IND_LOG_MIRROR_URLS',
    'IND_LOG_MIRROR_DIRS',
    'IND_LOG_PROOF_ARCHIVES',
    'IND_LOG_UNSAFE_SINGLE_MIRROR',
    'IND_LOG_MIN_MIRRORS',
    'IND_LOG_HOST',
    'IND_LOG_PORT',
    'IND_LOG_ROOT_INTERVAL_SECONDS',
    'IND_LOG_SUBMISSION_VERIFY_TIMEOUT_SECONDS',
)

_operator_env_previous = None


def local_operator_settings(base_dir):
    """Return localhost transparency settings for development-only desktop operator mode."""

    mirror_dir = str(Path(base_dir) / LOCAL_OPERATOR_MIRROR_DIR)
    return {
        'IND_SUBMIT_TO_TRANSPARENCY_LOG': '1',
        'IND_LOG_OPERATOR_URL': LOCAL_OPERATOR_URL,
        'IND_LOG_MIRROR_URLS': mirror_dir,
        'IND_LOG_MIRROR_DIRS': mirror_dir,
        'IND_LOG_PROOF_ARCHIVES': mirror_dir,
        'IND_LOG_UNSAFE_SINGLE_MIRROR': '1',
        'IND_LOG_MIN_MIRRORS': '1',
        'IND_LOG_HOST': '127.0.0.1',
        'IND_LOG_PORT': LOCAL_OPERATOR_URL.rsplit(':', 1)[-1],
        'IND_LOG_ROOT_INTERVAL_SECONDS': str(LOCAL_OPERATOR_ROOT_INTERVAL_SECONDS),
        'IND_LOG_SUBMISSION_VERIFY_TIMEOUT_SECONDS': str(
            LOCAL_OPERATOR_SUBMISSION_VERIFY_TIMEOUT_SECONDS
        ),
    }, mirror_dir


def apply_operator_environment(base_dir):
    """Temporarily install local-operator env vars and return a child-process env."""

    global _operator_env_previous
    settings, mirror_dir = local_operator_settings(base_dir)
    if _operator_env_previous is None:
        _operator_env_previous = {key: os.environ.get(key) for key in LOCAL_OPERATOR_ENV_KEYS}
    os.environ.update(settings)
    return os.environ.copy(), mirror_dir


def restore_operator_environment():
    """Restore process env vars changed by apply_operator_environment."""

    global _operator_env_previous
    if _operator_env_previous is None:
        return
    for key, value in _operator_env_previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    _operator_env_previous = None


def subprocess_kwargs(base_dir, env=None):
    kwargs = {
        'cwd': str(base_dir),
        'env': env or os.environ.copy(),
    }
    if platform.system() == 'Windows' and hasattr(subprocess, 'CREATE_NO_WINDOW'):
        kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
    return kwargs


def local_operator_command(base_dir, mirror_dir, python_executable=None):
    python_executable = python_executable or sys.executable
    base_dir = Path(base_dir)
    return [
        python_executable,
        str(base_dir / 'log_server.py'),
        '--host',
        '127.0.0.1',
        '--port',
        LOCAL_OPERATOR_URL.rsplit(':', 1)[-1],
        '--mirror-dir',
        str(mirror_dir),
        '--root-interval-seconds',
        str(LOCAL_OPERATOR_ROOT_INTERVAL_SECONDS),
    ]


def startup_bat_contents(base_dir, node_script, include_operator, python_executable=None):
    python_executable = python_executable or sys.executable
    base_dir = Path(base_dir)
    lines = ['@echo off', f'cd /d "{base_dir}"']
    if include_operator:
        settings, mirror_dir = local_operator_settings(base_dir)
        lines.extend(f'set {key}={value}' for key, value in settings.items())
        lines.append(
            f'start "" "{python_executable}" "{base_dir / "log_server.py"}" '
            f'--host 127.0.0.1 --port {LOCAL_OPERATOR_URL.rsplit(":", 1)[-1]} '
            f'--mirror-dir "{mirror_dir}" --root-interval-seconds {LOCAL_OPERATOR_ROOT_INTERVAL_SECONDS}'
        )
    lines.append(f'start "" "{python_executable}" "{node_script}"')
    return '\n'.join(lines) + '\n'
