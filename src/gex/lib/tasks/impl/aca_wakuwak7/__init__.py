'''Implementation of aca_wakuwak7: ACA NEOGEO WAKU WAKU 7.'''

import logging
import os
import struct
import zlib

from gex.lib.tasks import helpers
from gex.lib.tasks.basetask import BaseTask
from gex.lib.utils.blob import hash as hash_helper

logger = logging.getLogger('gextoolbox')


class AcaWakuWaku7Task(BaseTask):
    '''Extracts the Neo Geo data embedded in the Microsoft Store/Xbox release.'''

    _task_name = "aca_wakuwak7"
    _title = "ACA NEOGEO WAKU WAKU 7"
    _details_markdown = r'''
This task covers version 2.0.0.0 of ACA NEOGEO WAKU WAKU 7 from the
Microsoft Store/Xbox app.

The game executable contains eight gzip streams. They expand into the complete
Neo Geo M1, S1, P, V and C ROM regions. All twelve resulting chip images match
MAME's Waku Waku 7 hashes exactly.

ACA divides the 24 MiB sprite region into four 6 MiB streams. Their physical
order is 0, 2, 1, 3; after reordering, each 8 MiB pair deinterleaves into the
corresponding 4 MiB C ROMs.

The task emits both `wakuwak7.zip` and a MiSTer/NeoSD `wakuwak7.neo`
container. Both formats have been confirmed working on MiSTer hardware.

The executable may be supplied directly in the input directory or below its
`Content` subdirectory. A renamed executable is also detected by its exact
size and then verified by SHA-1. Microsoft Store package protection can deny
normal reads of the installed executable. This task does not bypass that
protection; in that case, point it at a readable personal backup.

Requires a Neo Geo BIOS ROM to use the ZIP with an emulator.
'''
    _default_input_folder = None
    _input_folder_desc = "Folder containing a readable WAKU WAKU 7.exe"

    _exe_name = "WAKU WAKU 7.exe"
    _source_size = 16186368
    _source_sha1 = "eb1c4ad5fbe8bb9ff508e25f9b13d2dd2e501931"

    _entry_crcs = {
        "225-c1.c1": "EE4FEA54",
        "225-c2.c2": "0C549E2D",
        "225-c3.c3": "AF0897C0",
        "225-c4.c4": "4C66527A",
        "225-c5.c5": "8ECEA2B5",
        "225-c6.c6": "0EB11A6D",
        "225-m1.m1": "0634BBA6",
        "225-p1.p1": "B14DA766",
        "225-p2.sp2": "FE190665",
        "225-s1.s1": "71C4B4B5",
        "225-v1.v1": "6195C6B4",
        "225-v2.v2": "6159C5FE"
    }

    _sprite_stream_order = (
        "3F3EA85D",
        "025CC948",
        "3BF0D696",
        "BE9D057E"
    )

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

        zip_name = 'wakuwak7.zip'
        zip_contents = helpers.build_zip(file_map)
        self._write_verified_output(out_dir, zip_name, zip_contents)

        neo_name = 'wakuwak7.neo'
        neo_contents = self._build_neo(file_map)
        self._write_verified_output(out_dir, neo_name, neo_contents)

        logger.info("Processing complete: verified Waku Waku 7 ZIP and NeoSD image recovered.")

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
        sprite_streams = {}

        for stream in self._gzip_streams(executable):
            stream_crc = self._crc(stream)

            if stream_crc == "0634BBA6":
                file_map["225-m1.m1"] = stream
            elif stream_crc == "71C4B4B5":
                file_map["225-s1.s1"] = stream
            elif stream_crc == "23A680A8" and len(stream) == 0x300000:
                file_map["225-p1.p1"] = stream[:0x100000]
                file_map["225-p2.sp2"] = stream[0x100000:]
            elif stream_crc == "D6D82BCE" and len(stream) == 0x800000:
                file_map["225-v1.v1"] = stream[:0x400000]
                file_map["225-v2.v2"] = stream[0x400000:]
            elif stream_crc in self._sprite_stream_order and len(stream) == 0x600000:
                sprite_streams[stream_crc] = stream

        if set(sprite_streams) == set(self._sprite_stream_order):
            ordered_tiles = b''.join(
                sprite_streams[stream_crc]
                for stream_crc in self._sprite_stream_order
            )
            for pair_index in range(3):
                pair_start = pair_index * 0x800000
                pair = ordered_tiles[pair_start:pair_start + 0x800000]
                odd_index = pair_index * 2 + 1
                even_index = odd_index + 1
                file_map[f"225-c{odd_index}.c{odd_index}"] = pair[0::2]
                file_map[f"225-c{even_index}.c{even_index}"] = pair[1::2]

        return file_map

    @staticmethod
    def _build_neo(file_map):
        '''Build a MiSTer/NeoSD .neo container from recovered chip images.'''
        prom = file_map['225-p1.p1'] + file_map['225-p2.sp2']
        srom = file_map['225-s1.s1']
        mrom = file_map['225-m1.m1']
        vrom = file_map['225-v1.v1'] + file_map['225-v2.v2']
        crom = AcaWakuWaku7Task._build_crom(file_map)

        header = bytearray(4096)
        struct.pack_into(
            '<4s10I', header, 0,
            b'NEO\x01', len(prom), len(srom), len(mrom), len(vrom), 0, len(crom),
            1996, 9, 175, 0x225
        )
        name = b'Waku Waku 7'
        manufacturer = b'Sunsoft'
        header[44:44 + len(name)] = name
        header[77:77 + len(manufacturer)] = manufacturer

        return b''.join((header, prom, srom, mrom, vrom, crom))

    @staticmethod
    def _build_crom(file_map):
        '''Interleave the six physical C ROMs into the NeoSD sprite region.'''
        crom = bytearray(0x1800000)
        offset = 0
        for pair_index in range(3):
            first_index = pair_index * 2 + 1
            second_index = first_index + 1
            first = file_map[f'225-c{first_index}.c{first_index}']
            second = file_map[f'225-c{second_index}.c{second_index}']
            pair_size = len(first) + len(second)
            crom[offset:offset + pair_size:2] = first
            crom[offset + 1:offset + pair_size:2] = second
            offset += pair_size
        return crom

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
