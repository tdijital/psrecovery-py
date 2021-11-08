# psrecovery-py
A prototype to explore different file recovery techniques for the UFS2 filesystem. Specifically for use with PS3/4. This application is built on top of [PS-HDD-Tools](https://github.com/aerosoul94/PS-HDD-Tools) the intention is to eventually implement these file recovery techniques into PS-HDD-Tools.

## Requirements

- Python 3.9+

## Usage

To open the app GUI:
`py main.py`

To open the app and begin scanning with CLI on a *DECRYPTED* hdd image:
`py main.py <hdd img> [args]`

To open the app and begin scanning with CLI on an *ENCRYPTED* hdd image:
`py main.py <hdd img> <key file> [args]`

Pass the argument `--deep-scan` to do a deep scan, by default the fast scan will be run.

## Shortcut Keys

- Find (ctrl-f)
  - Find Next (F3)
  - Find Previous (Shift-F3)

## FAQ

__Do I have to scan a hdd img everytime I open one?__
\
If the hdd img has been scanned before it will save the scan results to the `/scans` directory in the same folder as main.py. Each hdd img scan results will be put into a folder named in this schema `<hdd img file name><(fast)||(deep)>`. If psrecovery-py detects a folder fitting the schema with scan results for an img it will load from the saved files, otherwise it will begin a new scan. Scan results are only saved once the entire scan is completed.

__How does this work? Magic??__
\
Yes.
\
\
Also it works by recovering inodes and directs from a UFS2 filesystem. It then does a bunch of cool stuff to rebuild the filesystem.

__What's an inode?__
\
An inode stores all of a file or folder information with the exception of its name.

__What's a direct?__
\
A direct stores a file or folder name and a pointer to its inode.

__What do the different icons on the files and folders mean?__
\
<img src="https://user-images.githubusercontent.com/61374259/139726842-3e2e3fe4-4179-4f3d-bcf9-600d52bbe99e.png"
     alt="psrecovery-py icon key"
     width="300px"/>

__The file I want to recover has a *YELLOW* indicator am I out of luck?__
\
You may still be in luck. What we know for certain is that the block index table is overwritten so we can't say for certain where the data blocks are located for this file. When you dump the file psrecovery-py will make an assumption that the rest of the data blocks for this file fall in the following data blocks after the last valid data block for the file. This may or may not be accurate. When dumping files and folders a log file is written to the output folder, in that log it will indicate which files may be corrupt and at what offset.

__The file I want to recover has a *RED* indicator am I out of luck?__
\
You still may be in luck here too! Albeit this one is a bit more tough. The data very well may be on the drive -- it's even possible that it's one of the unknown inodes the scanner found. We just have no information to link the two. Hopefully the file carver which isn't implemented yet can help here. There will be some caveats though but I will cover those when the file carver is added.

__I recovered a file that had a *GREEN* checkmark and it was a corrupt file, whyyyy?!__
\
Currently psrecovery-py doesn't look for collisions between active files in the filesystem or between other deleted files. So likely the files data blocks were taken by a newer file. Unfortunately that likely means the data is overwritten and not present on the drive.

__There's a folder somewhere I know it shouldn't be, what's the deal?__
\
This can happen if a newer folder re-uses an old folders inode offset location. The children will stil reference the old parent folders inode offset. So as far as we can see it is a child of that parent.

__What happens when I dump a file with a red indicator?__
\
A 0kb file will be written in place of the file.

__What's the difference between deep scan and fast scan?__
\
Deep scan will search every single fragment in the drive for directs and inodes.
Fast scan only searches areas defined by the super block that contain inodes and directs.

__Why would I use deep scan?__
\
If the drive has been formatted multiple times sometimes that partition can change where it stores its inodes and directs, the fast scan would miss these if they aren't where it expects. __Deep scan has a potential to return false positives.__

## TODO
- Check for collisions between files
- Show active filesystem in results
- Better filtering of the scan results
- Implement FileCarver
- Use Unreal TOC files to identify unknown Inodes (and carved files when implemented)
- Scan for stray SuperBlocks and CylinderGroups if found use them in relevant directs to calculate ino to offset.

### Experimental TODO
- Scan for unclaimed indirect block tables
  - Try to identify file match for the block table in carved files.
