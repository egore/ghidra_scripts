# Ghidra helper scripts

This repo contains scripts I use to ease my work with Ghidra.

## LabelDefaultStringWithQuotes

If current address is a default string label (s_<...>_<addr>), rename it to the full string in quotes

## RemoveRenameStructureFieldComments

Remove "Created by Rename Structure Field action" comments from user-defined structure fields

## GoToPreviousLabel

Go to the previous label before the current address

# Usage

- Clone this repo into one of your Ghidra script directories (or add it via **Script Manager** -> **Script Directories**).
- In Ghidra, open **Window** -> **Script Manager**, find the script you want, then run it on the current program.

# License

This is using the [GNU General Public License v3.0](LICENSE).