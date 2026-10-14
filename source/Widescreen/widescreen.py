"""Parche reversible de la lista de resoluciones de esta edicion de WarBreeds.

Solo usa la biblioteca estandar. No inicia el juego ni prueba su HUD.
"""
import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import tempfile
import uuid

ORIGINAL_SHA256 = '0e0768693a62ba89fcd5f1fd56dfcda68206d32bc6d5b5c285792996115061e3'
TARGET = (1920, 1080)
SUPPORTED = 'native, 640x480, 800x600, 1024x768, 1152x864, 1280x1024, 1920x1080'
MARKER = '; WarBreeds 16:9 experimental - modos emulados'
PATCHES = (
    (0x9159B, bytes.fromhex('66 c7 44 24 14 80 04'), bytes.fromhex('66 c7 44 24 14 80 07')),
    (0x915A2, bytes.fromhex('66 c7 44 24 16 60 03'), bytes.fromhex('66 c7 44 24 16 38 04')),
    (0x12C8B0, '1152 x 864'.encode('utf-16le'), '1920x1080 '.encode('utf-16le')),
)
PACKAGE = Path(__file__).resolve().parent
ROOT = PACKAGE.parent.parent
EXE = ROOT / 'WARBREED.EXE'
PREFS = ROOT / 'DATA' / 'prefs.dbg'
CONFIG = ROOT / 'DDrawCompat-WARBREED.ini'
STATE = PACKAGE / 'state.json'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def atomic_write(path, data):
    descriptor, temporary = tempfile.mkstemp(prefix='wb16x9-', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save_state(state):
    atomic_write(STATE, (json.dumps(state, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))


def require_closed_game():
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)

    class Entry(ctypes.Structure):
        _fields_ = [('dwSize', wintypes.DWORD), ('cntUsage', wintypes.DWORD),
                    ('th32ProcessID', wintypes.DWORD), ('th32DefaultHeapID', ctypes.c_size_t),
                    ('th32ModuleID', wintypes.DWORD), ('cntThreads', wintypes.DWORD),
                    ('th32ParentProcessID', wintypes.DWORD), ('pcPriClassBase', wintypes.LONG),
                    ('dwFlags', wintypes.DWORD), ('szExeFile', wintypes.WCHAR * 260)]

    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.CreateToolhelp32Snapshot(2, 0)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), 'No se pudo comprobar si el juego esta cerrado.')
    try:
        entry = Entry()
        entry.dwSize = ctypes.sizeof(entry)
        found = kernel.Process32FirstW(handle, ctypes.byref(entry))
        while found:
            if entry.szExeFile.casefold() == 'warbreed.exe':
                raise RuntimeError('Cerrar WarBreeds antes de aplicar o restaurar el parche.')
            found = kernel.Process32NextW(handle, ctypes.byref(entry))
        if ctypes.get_last_error() != 18:
            raise OSError(ctypes.get_last_error(), 'No se completo la comprobacion de procesos.')
    finally:
        kernel.CloseHandle(handle)


def preference_fields(data):
    if data[:4] != b'MHWK' or data[8:12] != b'RSRC':
        raise ValueError('prefs.dbg no tiene el contenedor Mohawk esperado.')
    u16 = lambda offset: struct.unpack_from('>H', data, offset)[0]
    u32 = lambda offset: struct.unpack_from('>I', data, offset)[0]
    base = u32(20)
    table = base + u16(24)
    files = []
    for index in range(u32(table)):
        offset = table + 4 + index * 10
        position = u32(offset)
        size = u16(offset + 4) + (data[offset + 6] << 16) + ((data[offset + 7] & 7) << 24)
        if position + size > len(data):
            raise ValueError('Recurso de preferencias fuera del archivo.')
        files.append((position, size))
    strings = base + u16(base)
    result = {}
    for index in range(u16(base + 2)):
        offset = base + 4 + index * 8
        resources = base + u16(offset + 4)
        names_table = base + u16(offset + 6)
        names = {}
        for item in range(u16(names_table)):
            name_offset, file_index = struct.unpack_from('>HH', data, names_table + 2 + item * 4)
            start = strings + name_offset
            names[file_index] = data[start:data.index(0, start)].decode('ascii')
        for item in range(u16(resources)):
            _, file_index = struct.unpack_from('>HH', data, resources + 2 + item * 4)
            if not 1 <= file_index <= len(files):
                raise ValueError('Indice de preferencias invalido.')
            name = names.get(file_index)
            if name:
                if name in result:
                    raise ValueError('Preferencia duplicada: ' + name)
                result[name] = files[file_index - 1]
    for name in ('OPTNPRFRESW', 'OPTNPRFRESH'):
        if name not in result or result[name][1] != 2:
            raise ValueError('Falta la preferencia de resolucion esperada: ' + name)
    return result


def dimensions(data):
    fields = preference_fields(data)
    return tuple(struct.unpack_from('<H', data, fields[name][0])[0]
                 for name in ('OPTNPRFRESW', 'OPTNPRFRESH'))


def set_dimensions(data, size):
    fields = preference_fields(data)
    output = bytearray(data)
    for name, value in zip(('OPTNPRFRESW', 'OPTNPRFRESH'), size):
        if not 640 <= value <= 32767:
            # La altura nativa puede ser 480 al restaurar.
            if not (name == 'OPTNPRFRESH' and 480 <= value <= 32767):
                raise ValueError('Dimension fuera del rango seguro.')
        struct.pack_into('<H', output, fields[name][0], value)
    return bytes(output)


def patch_executable(data):
    if sha(data) != ORIGINAL_SHA256:
        raise ValueError('Ejecutable no compatible. No se modifico ningun archivo.')
    output = bytearray(data)
    for offset, before, after in PATCHES:
        if data[offset:offset + len(before)] != before or len(before) != len(after):
            raise ValueError('La firma de una instruccion o etiqueta no coincide.')
        output[offset:offset + len(after)] = after
    return bytes(output)


def ini_value(text, key):
    values = re.findall(r'^\s*' + re.escape(key) + r'\s*=\s*([^;#\r\n]*)', text, re.I | re.M)
    return values[-1].strip() if values else None


def set_ini_value(text, key, value):
    lines = [line for line in text.splitlines(keepends=True)
             if not re.match(r'^\s*' + re.escape(key) + r'\s*=', line, re.I)]
    output = ''.join(lines)
    if value is not None:
        if output and not output.endswith(('\n', '\r')):
            output += '\r\n'
        output += f'{key} = {value}\r\n'
    return output


def verified_state():
    state = json.loads(STATE.read_text(encoding='utf-8'))
    backup = (PACKAGE / state['backup']).resolve()
    if not backup.is_relative_to((PACKAGE / 'backups').resolve()):
        raise ValueError('Ruta de respaldo fuera del paquete.')
    original = (backup / 'WARBREED.EXE').read_bytes()
    patched = patch_executable(original)
    if state['patched_sha256'] != sha(patched):
        raise ValueError('El estado no coincide con el parche esperado.')
    return state, backup, original, patched


def menu_layer_active(current):
    menu_state = ROOT / 'MODS' / 'Menu-Art' / 'installed-state.json'
    if not menu_state.exists():
        return False
    report = json.loads(menu_state.read_text(encoding='utf-8'))
    return any(entry.get('path') == 'WARBREED.EXE' and
               entry.get('installed_sha256') == sha(current)
               for entry in report.get('files', []))


def video_layout_layer_active(current):
    path = ROOT / 'MODS' / 'Video-Layout' / 'state.json'
    if not path.exists():
        return False
    report = json.loads(path.read_text(encoding='utf-8'))
    return any(entry.get('path') == 'WARBREED.EXE' and
               entry.get('installed_sha256') == sha(current)
               for entry in report.get('files', []))


def zoom_layer_active(current):
    if video_layout_layer_active(current):
        return True
    path = ROOT / 'MODS' / 'Camera-Zoom' / 'state.json'
    if not path.exists():
        return False
    report = json.loads(path.read_text(encoding='utf-8'))
    return any(entry.get('path') == 'WARBREED.EXE' and
               entry.get('installed_sha256') == sha(current)
               for entry in report.get('files', []))


def ui_layer_active(current):
    if zoom_layer_active(current):
        return True
    path = ROOT / 'MODS' / 'UI-Animation' / 'state.json'
    if not path.exists():
        return False
    report = json.loads(path.read_text(encoding='utf-8'))
    return any(entry.get('path') == 'WARBREED.EXE' and
               entry.get('installed_sha256') == sha(current)
               for entry in report.get('files', []))


def animation_layer_active(current):
    if ui_layer_active(current):
        return True
    animation_state = ROOT / 'MODS' / 'Animation-Timing' / 'state.json'
    if not animation_state.exists():
        return False
    report = json.loads(animation_state.read_text(encoding='utf-8'))
    return any(entry.get('path') == 'WARBREED.EXE' and
               entry.get('installed_sha256') == sha(current)
               for entry in report.get('files', []))


def apply():
    require_closed_game()
    current = EXE.read_bytes()
    if animation_layer_active(current):
        print('16:9 ya esta instalado junto con los relojes de animacion; no se cambiaron preferencias.')
        return
    if menu_layer_active(current):
        print('16:9 ya esta instalado junto con los fondos de menus; no se cambiaron preferencias.')
        return
    if sha(current) != ORIGINAL_SHA256:
        if STATE.exists():
            _, _, _, patched = verified_state()
            if current == patched:
                print('El parche ya esta instalado; no se cambiaron preferencias.')
                return
        raise ValueError('Ejecutable distinto de la version compatible; operacion cancelada.')
    patched = patch_executable(current)
    preferences = PREFS.read_bytes()
    old_dimensions = dimensions(preferences)
    config_bytes = CONFIG.read_bytes()
    config = config_bytes.decode('utf-8-sig')
    overlay_path = ROOT / 'DDrawCompatOverlay-WARBREED.ini'
    overlay = overlay_path.read_text(encoding='utf-8-sig') if overlay_path.exists() else ''
    aspect = ini_value(overlay, 'DisplayAspectRatio') or ini_value(config, 'DisplayAspectRatio') or 'app'
    if aspect.casefold() != 'app':
        raise ValueError('Usar DisplayAspectRatio=app antes de aplicar para conservar proporciones.')
    if ini_value(overlay, 'SupportedResolutions') is not None:
        raise ValueError('El overlay redefine SupportedResolutions; revisar antes de aplicar.')
    old_supported = ini_value(config, 'SupportedResolutions')
    config = set_ini_value(config, 'SupportedResolutions', SUPPORTED)
    if MARKER not in config:
        config += MARKER + '\r\n'
    backup = PACKAGE / 'backups' / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex)
    backup.mkdir(parents=True, exist_ok=False)
    for source in (EXE, PREFS, CONFIG):
        shutil.copy2(source, backup / source.name)
    if STATE.exists():
        shutil.copy2(STATE, backup / 'previous-state.json')
    state = {'status': 'prepared', 'backup': backup.relative_to(PACKAGE).as_posix(),
             'original_sha256': ORIGINAL_SHA256, 'patched_sha256': sha(patched),
             'original_dimensions': list(old_dimensions), 'target_dimensions': list(TARGET),
             'original_supported_resolutions': old_supported, 'applied_supported_resolutions': SUPPORTED}
    save_state(state)
    written = []
    try:
        for destination, original, output in (
            (CONFIG, config_bytes, config.encode('utf-8')),
            (PREFS, preferences, set_dimensions(preferences, TARGET)),
            (EXE, current, patched),
        ):
            atomic_write(destination, output)
            written.append((destination, original))
        state['status'] = 'applied-unverified-in-game'
        save_state(state)
    except Exception:
        for destination, original in reversed(written):
            atomic_write(destination, original)
        state['status'] = 'rolled-back-after-error'
        save_state(state)
        raise
    print('Instalado: 1920x1080 sustituye 1152x864. Se conserva 1280x1024.')
    print('Preferencias preparadas en 1920x1080; no se modifico la velocidad.')
    print('Prueba visual pendiente del usuario. Respaldo: ' + str(backup))


def restore():
    require_closed_game()
    if video_layout_layer_active(EXE.read_bytes()):
        raise ValueError('Restaurar primero MODS\\Video-Layout\\Restaurar-videos-pantalla.cmd.')
    current = EXE.read_bytes()
    if zoom_layer_active(current):
        raise ValueError('Restaurar primero MODS\\Camera-Zoom\\Restaurar-zoom.cmd; despues UI, cursor/aro y 16:9.')
    if ui_layer_active(current):
        raise ValueError('Restaurar primero MODS\\UI-Animation\\Restaurar-UI.cmd, despues cursor/aro y 16:9.')
    if animation_layer_active(current):
        raise ValueError('Restaurar primero las animaciones con MODS\\Animation-Timing\\Restaurar-animaciones.cmd; despues restaurar 16:9.')
    if menu_layer_active(current):
        raise ValueError('Restaurar primero los menus con MODS\\Menu-Art\\Restaurar-menus.cmd; despues restaurar 16:9.')
    state, backup, original, patched = verified_state()
    if current not in (original, patched):
        raise ValueError('El ejecutable tiene otros cambios; no se sobrescribira.')
    preferences = PREFS.read_bytes()
    if dimensions(preferences) == TARGET:
        original_preferences = (backup / 'prefs.dbg').read_bytes()
        preferences = set_dimensions(preferences, dimensions(original_preferences))
    config_bytes = CONFIG.read_bytes()
    config = config_bytes.decode('utf-8-sig')
    if ini_value(config, 'SupportedResolutions') == SUPPORTED:
        config = set_ini_value(config, 'SupportedResolutions', state['original_supported_resolutions'])
        config = ''.join(line for line in config.splitlines(keepends=True) if line.strip() != MARKER)
    history = backup / ('before-restore-' + uuid.uuid4().hex)
    history.mkdir()
    for source in (EXE, PREFS, CONFIG):
        shutil.copy2(source, history / source.name)
    written = []
    try:
        for destination, before, after in ((EXE, current, original), (PREFS, PREFS.read_bytes(), preferences),
                                           (CONFIG, config_bytes, config.encode('utf-8'))):
            atomic_write(destination, after)
            written.append((destination, before))
        state['status'] = 'restored'
        save_state(state)
    except Exception:
        for destination, before in reversed(written):
            atomic_write(destination, before)
        raise
    print('Ejecutable original restaurado; se conservaron los filtros y otras preferencias actuales.')


def status():
    current = EXE.read_bytes()
    state = 'original'
    if sha(current) != ORIGINAL_SHA256:
        state = 'unknown'
        if animation_layer_active(current):
            state = 'patched-1920x1080-with-animation-timing'
        elif menu_layer_active(current):
            state = 'patched-1920x1080-with-menu-backgrounds'
        elif STATE.exists():
            _, _, _, patched = verified_state()
            if current == patched:
                state = 'patched-1920x1080'
    print(json.dumps({'executable': state, 'sha256': sha(current),
                      'saved_resolution': dimensions(PREFS.read_bytes()),
                      'runtime_validation': 'a cargo del usuario'}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='WarBreeds: prueba reversible de 1920x1080.')
    parser.add_argument('command', choices=('apply', 'restore', 'status'))
    arguments = parser.parse_args()
    try:
        {'apply': apply, 'restore': restore, 'status': status}[arguments.command]()
    except (OSError, ValueError, RuntimeError, KeyError, struct.error) as error:
        parser.exit(1, 'ERROR: ' + str(error) + '\n')
