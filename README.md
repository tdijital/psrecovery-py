# psrecovery-py
A prototype to explore different recovery techniques for the UFS2 filesystem. Specifically for use with PS3/4.

## TODO
- [x] Improve file dumping time.
- [x] Add more validation for the inode scanner.
- [x] Add an option to scan for inodes and directs accross the whole drive.
- [x] Include PS4 support
- [ ] Check if a recovered inode's datablocks are taken by files in the existing fs
- [ ] Implement file carver scanner
- [ ] Use file signatures to identify unidentified Inode file types
- [ ] Use Unreal TOC files to identify inodes with no direct.
- [ ] Use Unreal TOC files to identify carved files

### Experimental TODO
- [ ] Scan for unclaimed inidrect block tables
- - [ ] Match unidentified carved files with a file size in their header to nearby block table that fits the file.