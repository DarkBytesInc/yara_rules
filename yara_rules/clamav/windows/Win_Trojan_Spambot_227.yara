rule Win_Trojan_Spambot_227
{
strings:
	$a0 = { 6232afb2fffffdffb3159408fd1f113311b69e87d9e51b7a8c095aa11056981e13ea3a9ac4ffffffff68d9c111cb347fbebdf3da6316de4a4f4143160bd925490f9dacb43546d84656ffffffff7affca7863f06fa50f57f1d5778a2427f3b41d0aaa4bf63c70cd24bad8e56656fd }

condition:
	$a0
}

        
