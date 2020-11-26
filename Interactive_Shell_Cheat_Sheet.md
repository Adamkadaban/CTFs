# Upgrading to an interactive shell through netcat

* Install `rlwrap on your system`
* Now, every time you run a nc listener, just put `rlwrap in front`
* For example: `rlwrap nc -lvnp 1337`
	* This will give you a fully interactive shell (as far as I can tell) for windows and *nix systems




### OLD VERSION

1. Run the following python command to make it partially interactive: `python -c 'import pty;pty.spawn("/bin/bash");'`
2. Exit the netcat session with `CTRL+Z` and run `stty raw -echo` locally
3. Reenter your session with the command `fg` (and the job id afterward if needed)
4. Change your terminal emulator to xterm by running `export TERM=xterm` (this might not be necessary)
5. Change your shell to bash by running `export SHELL=bash` (this might not be necessary)
6. Done! Now your shell should be fully ainteractive



