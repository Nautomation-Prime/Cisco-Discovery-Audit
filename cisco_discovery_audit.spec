# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import copy_metadata


datas = copy_metadata("nautomation-prime-cisco-discovery-audit")

analysis = Analysis(
    ["scripts/launcher.py"],
    pathex=["."],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "IPython",
        "matplotlib",
        "numpy",
        "pandas",
        "pytest",
        "scipy",
        "sqlalchemy",
        "tkinter",
        "zmq",
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(analysis.pure)

exe = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="NautomationPrimeCiscoDiscoveryAudit",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
)

collection = COLLECT(
    exe,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    name="NautomationPrimeCiscoDiscoveryAudit",
)
