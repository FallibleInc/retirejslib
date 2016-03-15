### Port of RetireJS in Python

#### Specifically:

* https://github.com/RetireJS/retire.js/blob/master/node/lib/retire.js  as retirejs.py . How to convert:
	1. convert dot access to dict access in python, 
	2. function to def, 
	3. && and || to `and` and `or` respectively, 
	4. regex match to re.search
	5. `null` to `None`
	6. ternerary operator change 
	7. `for loop` change where required (mostly not required)
	8. `if` is mostly as it is
* https://github.com/RetireJS/retire.js/blob/master/repository/jsrepository.json as repo.py . How to convert: 
	1.  Replace `\\` with `\` , 
	2.  replace `$$version$$` with `[0-9][0-9.a-z_\-]+`

* And test from https://github.com/RetireJS/retire.js/tree/master/node/spec/tests as test_requirejs.py
