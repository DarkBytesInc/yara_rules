rule Win_Trojan_Fruit_2
{
strings:
	$a0 = { b8c614ba38010500003b060200722ab409ba1c01cd21b8014ccd214e6f7420656e6f756768206d656d6f7279242020 }

condition:
	$a0
}

        
