* Here I have 2 solutions.
* `solv.py` is brute-force and solves using angr 
	* However, it _does_ take a very long time

* `smartSolv.py` uses the fact that the code checks 1 byte of the flag at a time to see which characters are correct
