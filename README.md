# psrecovery-py
A prototype to explore different recovery techniques for the UFS2 filesystem. Specifically for use with PS3/4.

## TODO
- [x] Improve file dumping time.
- [ ] Include progress bar when dumping files.
- [ ] Add more validation for the inode scanner.
- [x] Add an option to scan for inodes and directs accross the whole drive.
- [ ] Include PS4 support
- [ ] Use Unreal TOC files to identify inodes with no direct.
- [ ] Check if a recovered inode's datablocks are taken by files in the existing fs
