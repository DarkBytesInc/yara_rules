rule Win_Trojan_Dodo_3
{
strings:
	$a0 = { 444f444f00e980139090909090bf8814b800008ec026a1f0013d444f750c26a1f2013d444f75f5e9c306e9a000 }

condition:
	$a0
}

        
