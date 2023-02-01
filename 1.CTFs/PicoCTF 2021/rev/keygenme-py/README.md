* I modified the original python file to print out the key
* The important part is that they already give you most of the flag in `key_part_static1_trial`:
	```
	key_part_static1_trial = "picoCTF{1n_7h3_|<3y_of_"
	key_part_dynamic1_trial = "f911a486"
	key_part_static2_trial = "}"
	key_full_template_trial = key_part_static1_trial + key_part_dynamic1_trial + key_part_static2_trial
	```

* The `check_key()` function they give checks the first part of the flag and then the second
	* It checks the second 1 character at a time with lines similar to:
		`hashlib.sha256(username_trial).hexdigest()[4]`
	* Thus, just add the characters from what they are checking to get the 2nd part of the flag

* The flag is `picoCTF{1n_7h3_|<3y_of_f911a486}`
