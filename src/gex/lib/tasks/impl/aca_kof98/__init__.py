'''Implementation of aca_kof98: ACA NEOGEO THE KING OF FIGHTERS '98'''

import logging
import os
import struct
import zlib

from gex.lib.tasks import helpers
from gex.lib.tasks.basetask import BaseTask
from gex.lib.utils.blob import hash as hash_helper

logger = logging.getLogger('gextoolbox')


class AcaKof98Task(BaseTask):
    '''Extracts the Neo Geo data embedded in the Microsoft Store/Xbox release.'''

    _task_name = "aca_kof98"
    _title = "ACA NEOGEO THE KING OF FIGHTERS '98"
    _details_markdown = r'''
This task covers version 2.2.0.0 of ACA NEOGEO THE KING OF FIGHTERS '98
from the Microsoft Store/Xbox app.

The game executable contains eight gzip streams. They expand into the Neo Geo
M1, S1, program, V-ROM and interleaved C-ROM regions. Fifteen resulting chip
images match MAME's KOF '98 hashes exactly.

The exception is P1. ACA stores a non-stock 1 MiB decrypted/patched runtime
image. It works in the unprotected `kof98h` layout as `242-pn1.p1`. ACA's
stock parent-set M1 is correspondingly placed in the `242-mg1.m1` slot. These
two files do not match the canonical `kof98h` CRCs, so strict MAME audits will
report them, but the resulting set has been confirmed working on MiSTer.

The task emits both `kof98h.zip` and a MiSTer/NeoSD `kof98h.neo` container.

The executable may be supplied directly in the input directory or below its
`Content` subdirectory. A renamed executable is also detected by its exact
size and then verified by SHA-1. Microsoft Store package protection can deny
normal reads of the installed executable. This task does not bypass that
protection; in that case, point it at a readable personal backup.

Requires a Neo Geo BIOS ROM to use the recovered data with an emulator.
'''
    _default_input_folder = None
    _input_folder_desc = "Folder containing a readable THE KING OF FIGHTERS 98.exe"

    _exe_name = "THE KING OF FIGHTERS 98.exe"
    _source_size = 42989056
    _source_sha1 = "a7b608b6fbb5f4b9da498a4f635e14771fe6e8f0"

    _entry_crcs = {
        "242-c1.c1": "E564ECD6",
        "242-c2.c2": "BD959B60",
        "242-c3.c3": "22127B4F",
        "242-c4.c4": "0B4FA044",
        "242-c5.c5": "9D10BED3",
        "242-c6.c6": "DA07B6A2",
        "242-c7.c7": "F6D7A38A",
        "242-c8.c8": "C823E045",
        "242-mg1.m1": "4EF7016B",
        "242-pn1.p1": "BA09784A",
        "242-p2.sp2": "980ABA4C",
        "242-s1.s1": "7F7B4805",
        "242-v1.v1": "B9EA8051",
        "242-v2.v2": "CC11106E",
        "242-v3.v3": "044EA4E1",
        "242-v4.v4": "7985EA30"
    }

    def get_out_file_info(self):
        '''Return a list of output files.'''
        return {
            "files": self._metadata['out']['files'],
            "notes": self._metadata['out']['notes']
        }

    def execute(self, in_dir, out_dir):
        exe_path = self._find_executable(in_dir)
        logger.info(f"Reading {exe_path}...")
        try:
            with open(exe_path, 'rb') as in_file:
                executable = in_file.read()
        except PermissionError as error:
            raise PermissionError(
                "Windows package protection denied access to the game executable. "
                "Use a readable personal backup as the input source."
            ) from error

        source_sha1 = hash_helper.get_sha1(executable)
        if source_sha1 != self._source_sha1:
            raise ValueError(
                f"Unsupported executable revision: SHA-1 {source_sha1}; "
                f"expected {self._source_sha1}."
            )

        logger.info("Recovering embedded gzip streams...")
        file_map = self._recover_files(executable)
        self._verify_files(file_map)

        zip_name = 'kof98h.zip'
        zip_contents = helpers.build_zip(file_map)
        self._write_verified_output(out_dir, zip_name, zip_contents)

        neo_name = 'kof98h.neo'
        neo_contents = self._build_neo(file_map)
        self._write_verified_output(out_dir, neo_name, neo_contents)

        logger.info("Processing complete: playable kof98h ZIP and MiSTer/NeoSD image recovered.")

    def _write_verified_output(self, out_dir, filename, contents):
        verification = self.verify_out_file(filename, contents)
        if verification is not True:
            raise ValueError(f"Generated {filename} failed output verification: {verification}")

        out_path = os.path.join(out_dir, filename)
        with open(out_path, 'wb') as out_file:
            logger.info(f"Writing verified {filename}...")
            out_file.write(contents)

    def _find_executable(self, in_dir):
        candidates = [
            os.path.join(in_dir, self._exe_name),
            os.path.join(in_dir, 'Content', self._exe_name)
        ]
        for candidate in candidates:
            if os.path.isfile(candidate):
                return candidate

        for parent in (in_dir, os.path.join(in_dir, 'Content')):
            if not os.path.isdir(parent):
                continue
            for entry in os.scandir(parent):
                if (entry.is_file() and entry.name.lower().endswith('.exe')
                        and entry.stat().st_size == self._source_size):
                    return entry.path

        raise FileNotFoundError(
            f"Could not find {self._exe_name} or another {self._source_size}-byte "
            f"executable in {in_dir} or its Content directory."
        )

    @staticmethod
    def _gzip_streams(executable):
        '''Return all valid gzip members embedded in the executable.'''
        streams = []
        start = 0
        while True:
            offset = executable.find(b'\x1f\x8b\x08', start)
            if offset < 0:
                return streams
            start = offset + 1

            try:
                inflater = zlib.decompressobj(31)
                output = inflater.decompress(executable[offset:]) + inflater.flush()
            except zlib.error:
                continue

            if inflater.eof:
                streams.append(output)

    def _recover_files(self, executable):
        file_map = {}
        crc_to_name = {crc: name for name, crc in self._entry_crcs.items()}

        for stream in self._gzip_streams(executable):
            stream_crc = self._crc(stream)

            if stream_crc in ("4EF7016B", "7F7B4805"):
                file_map[crc_to_name[stream_crc]] = stream
            elif len(stream) == 0x500000:
                file_map["242-pn1.p1"] = stream[:0x100000]
                file_map["242-p2.sp2"] = stream[0x100000:]
            elif len(stream) == 0x1000000:
                quarters = [
                    stream[offset:offset + 0x400000]
                    for offset in range(0, len(stream), 0x400000)
                ]
                quarter_crcs = [self._crc(part) for part in quarters]
                if all(crc in crc_to_name and crc_to_name[crc].startswith('242-v')
                       for crc in quarter_crcs):
                    for crc, part in zip(quarter_crcs, quarters):
                        file_map[crc_to_name[crc]] = part
                    continue

                for part in (stream[0::2], stream[1::2]):
                    part_crc = self._crc(part)
                    name = crc_to_name.get(part_crc)
                    if name and name.startswith('242-c'):
                        file_map[name] = part

        return file_map

    @staticmethod
    def _build_neo(file_map):
        '''Build a MiSTer/NeoSD .neo container from recovered chip images.'''
        prom = file_map['242-pn1.p1'] + file_map['242-p2.sp2']
        srom = file_map['242-s1.s1']
        mrom = file_map['242-mg1.m1']
        vrom = b''.join(file_map[f'242-v{index}.v{index}'] for index in range(1, 5))

        crom_parts = [file_map[f'242-c{index}.c{index}'] for index in range(1, 9)]
        crom = bytearray(sum(len(part) for part in crom_parts))
        offset = 0
        for even, odd in zip(crom_parts[0::2], crom_parts[1::2]):
            pair_size = len(even) + len(odd)
            crom[offset:offset + pair_size:2] = even
            crom[offset + 1:offset + pair_size:2] = odd
            offset += pair_size

        header = bytearray(4096)
        struct.pack_into(
            '<4s10I', header, 0,
            b'NEO\x01', len(prom), len(srom), len(mrom), len(vrom), 0, len(crom),
            1998, 9, 72, 0x242
        )
        name = b"The King of Fighters '98 ACA"
        manufacturer = b'SNK'
        header[44:44 + len(name)] = name
        header[77:77 + len(manufacturer)] = manufacturer

        return b''.join((header, prom, srom, mrom, vrom, crom))

    def _verify_files(self, file_map):
        missing = set(self._entry_crcs).difference(file_map)
        extra = set(file_map).difference(self._entry_crcs)
        if missing or extra:
            raise ValueError(
                f"Embedded payload layout did not match this release; "
                f"missing={sorted(missing)}, extra={sorted(extra)}"
            )

        for name, expected_crc in self._entry_crcs.items():
            actual_crc = self._crc(file_map[name])
            if actual_crc != expected_crc:
                raise ValueError(
                    f"Recovered file {name} has CRC {actual_crc}; expected {expected_crc}."
                )

    @staticmethod
    def _crc(contents):
        return f"{zlib.crc32(contents) & 0xffffffff:08X}"
