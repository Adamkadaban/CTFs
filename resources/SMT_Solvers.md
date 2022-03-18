# SMT Solvers

# 1. z3

### Theories Include:

- Booleans
- Real numbers
- Bit vectors
    - basically a list of individual 1s and 0s (bits lol)
- Algebraic data types (lists, arrays, tuples...)

### Data types (all called sorts)

- IntSort
- RealSort
- BoolSort
- ArraySort
- BitVecSort
- ListSort
- ...

### Setup

1. Install z3
2. import in file
3. declare variables
4. create solver object
5. add constraints to solver
6. solve

### Boolean Logic

```python
# pip install z3-solver
from z3 import *

p = Bool('p')
q = Bool('q')
r = Bool('r')

s = Solver()

s.add(Implies(p,q)) # add contsraint that p->q

s.add(r==Not(q),Or(Not(p),r)) # add multiple constraints at once

s.check() # check if there is a possible solution

m = s.model() # get values

p_res = m[p] # get evaluation of variable

print(f"p={str(m.eval(p, model_completion=True)}")
# p = <val>

```

### Integer Logic

```python
# pip install z3-solver
from z3 import *

x = Int('x')
y = Int('y')
z = Int('z')

s = Solver()

n = big

s.add(x*x + y*y == z*z, 0<x, x<n, 0<y, y<n, 0<z, z<n)

s.check()
m = s.model()

x_res = m[x]
y_res = m[y]
z_res = m[z]

# Need to convert back from z3 symbolic data type to int
x_res = x_res.as_long()
y_res = y_res.as_long()
z_res = z_res.as_long()

print(m)

```

### BitVectors

```python
# pip install z3-solver
from z3 import *

a = BitVec('a',8) # 8 bit bit-vector
b = BitVec('b',64) # name, positive bit-length

s = Solver()

s.add(a*a == 289) # doesn't work, bc 8 bits can have max 256 value
									# Instead: this returns a*a % 256 = 33
s.add(b*b == 289) # does work

# You can't promote types with bitvectors
# a + b gets an error bc of diff sizes

s.check()
m = s.model()

```

## Ex.

### Problem

- Find an input string that prints "Correct"

```java
public class Hasher {
  private static boolean hash(final String s) {
    int n = 7;
    final int n2 = 593779930;
    for (int i = 0; i < s.length(); ++i) {
      n = n * 31 + s.charAt(i);
    }
    return n == n2;
  }
  public static void main(final String[] array) {
    if (array.length != 1) {
      System.out.println("Usage: java Hasher <password>");
      System.exit(1);
    }
    if (hash(array[0])) {
      System.out.println("Correct");
    }
    else {
      System.out.println("Incorrect");
    }
  }
}
```

### Solution

```python
from z3 import *

flag_length = 6

names = [f'x{i}' for i in range(flag_length)] # creating all the variable names

chars = [Int(n) for n in names] # list of symbolic integers

# do the problem
n = 7
n2 = 593779930

for c in chars:
	n = n*31 + c

# prevents integer overflow for the variable
ret = (n % (2**32)) == n2

s = Solver()
s.add(ret)

for c in chars:
	s.add(ord('a') <= c, c <= ord('z')) # add constraints for lowercase alpha
if s.check().r != 1:
	print("can't solve!")
else:
	m = s.model()
	flag = "".join([chr(m[c].as_long()) for c in chars])
	print(flag)

```

- The flag is `dragon`

# 2. angr

```python
import angr
import claripy

proj = angr.Project("./binaryName")
proj.arch # returns program architecture

state = proj.factory.entry_state()
state.regs.rax # gives us value of rax register at this point

simgr = proj.factory.simulation_manager(state)

simgr.explore() # run until the program stops
simgr.deadended[0].posix.dumps(1) # 1 is the fd for stdout
																	# get 0th element 
# If we wanted to, we could loop through all the elements until
# we see the input we want

# Now lets make angr explore but only until we get where we want

simgr = proj.factory.simulation_manager(state)
simgr.explore(find = lambda newState: b"String in correct output" in newState.posix.dumps(1))

simgr.found[0] # will give us the state

simgr.found[0].posix.dumps(1) # stdout that we want
simgr.found[0].posix.dumps(0) # stdin that gives us the correct stdout
```

### boilerplate

```python
import angr

binaryName = ""
winAddress = [] # can be array of ints or single int
loseAddress = []

p = angr.Project(binaryName)
simgr = p.factory.simulation_manager(p.factory.full_init_state())
simgr.explore(find=winAddress, avoid=loseAddress)

print(simgr.found[0].posix.dumps(0))

```

### super duper boilerplate code

```python
import angr
import claripy

proj = angr.Project("./binaryName")

state = proj.factory.entry_state()

simgr = proj.factory.simulation_manager(state)
simgr.explore(find = lambda newState: b"String in correct output" in newState.posix.dumps(1))

simgr.found[0] # will give us the state

print(simgr.found[0].posix.dumps(0)) # stdin that gives us the correct stdout
```

### using argv

```python
import angr
import claripy

binaryName = ""
proj = angr.Project(binaryName, load_options={"auto_load_libs": False})
argv1 = claripy.BVS("argv1", 0xE * 8)
initial_state = proj.factory.entry_state(args=[binaryName, argv1]) 

sm = proj.factory.simulation_manager(initial_state)
sm.explore(find=0x4018f7, avoid=0x4018f9)
found = sm.found[0]
return found.solver.eval(argv1, cast_to=bytes)
```

### good code (from CTF)

```python
import angr
import claripy

max_flag_length = 40

base_address = 0x00100000 # first location of the program

success_address = 0x0010134d # where the success function is called
failure_address = 0x0010135b # all the fails

proj = angr.Project('./proprietary', main_opts={"base_addr":base_address})

# BVS means a (symbolic, bit vector)
flag_chars = [claripy.BVS(f'flag{i}', 8) for i in range(max_flag_length)]

# BVV means a (value, bit vector)
# b'' turns the character into a byte 
# add \n in order to allow input to be accepted
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')]) 

state = proj.factory.full_init_state(
	args=['./proprietary'],
	add_options = angr.options.unicorn,
	stdin = flag
)
for c in flag_chars:
	state.solver.add(c >= ord('!'))
	state.solver.add(c <= ord('~'))

simmgr = proj.factory.simulation_manager(state)
simmgr.explore(find=success_address)

if len(simmgr.found)>0:
	for found in simmgr.found:
		print(found.posix.dumps(0))
else:
	print("found nothing")
```