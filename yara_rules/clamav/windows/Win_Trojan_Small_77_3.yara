rule Win_Trojan_Small_77_3
{
strings:
	$a0 = { bb677875641bb66d6fb729786ee37862003c6e0c6704f6ffffdd74d577627a0061637465756661006f63666a6769637269 }

condition:
	$a0
}

        
