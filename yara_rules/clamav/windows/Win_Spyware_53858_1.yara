rule Win_Spyware_53858_1
{
strings:
	$a0 = { c745e8673d2573c745ec26733d25c745f073266170c745f470656e64c745f83d256400e8 }

condition:
	$a0
}

        
