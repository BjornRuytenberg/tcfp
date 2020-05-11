# Thunderbolt Controller Firmware Patcher
Thunderbolt Controller Firmware Patcher, or tcfp, is a proof of concept that is used as part of the Thunderspy attacks as detailed at [thunderspy.io](https://thunderspy.io). This readme is a work in progress.

## Requirements
Thunderbolt Controller Firmware Patcher requires Python 3.4 or later.

## Usage
```
usage: tcfp.py [-h] [-v] {parse,patch} ...

Thunderbolt 3 Host Controller Firmware Patcher

positional arguments:
  {parse,patch}
    parse        Parse firmware image metadata and Security Level.
    patch        Patch firmware image to override Security Level to SL0 (no security).

optional arguments:
  -h, --help     show this help message and exit
  -v, --version  Show program's version number and exit.

(c) 2020 Björn Ruytenberg <bjorn@bjornweb.nl>. Licensed under GPLv3.
```

## Disclaimer
This code has been exclusively released for research purposes and is not intended for unlawful actions.
 
## License
See the [LICENSE](LICENSE) file.
