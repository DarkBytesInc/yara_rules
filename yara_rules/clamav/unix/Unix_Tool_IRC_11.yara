rule Unix_Tool_IRC_11
{
strings:
	$a0 = { a05044148e82daa82a48e7ff89308880b76972632e6f627365f92df6db727602732e6e6574110f69 }

condition:
	$a0
}

        
