* When we extract the archive, we see a git repo
* Theres nothing in the `secrets` file so we can run `git log` to see old commits:
```
commit 14a5c7088e7638abb2232c8cac1c7dd4687819f0 (HEAD)
Merge: 7e29273 7b82ac0
Author: Carlos Staszeski <cstaszeski@gmail.com>
Date:   Thu Mar 15 20:31:39 2018 -0400

    WIP on master: 7e29273 vegan!

commit 7b82ac03c49c0b55a4a8b8ffb3c04c5fe565fba6
Author: Carlos Staszeski <cstaszeski@gmail.com>
Date:   Thu Mar 15 20:31:39 2018 -0400

    index on master: 7e29273 vegan!

commit 7e2927361b7e4101e07fc5a475bb244622a275e3
Author: Carlos Staszeski <cstaszeski@gmail.com>
Date:   Thu Mar 15 20:29:53 2018 -0400

    vegan!
```
* Running `git checkout <commit>` doesn't seem to get us anywhere

* However, if we run `git fsck` to show dangling commits, we see one:
```
Checking object directories: 100% (256/256), done.
dangling commit 14a5c7088e7638abb2232c8cac1c7dd4687819f0
```
* If we write `git checkout 14a5c7088e7638abb2232c8cac1c7dd4687819f0` and cat the file, we get the flag:
	* sun{git_gud_k1d}

