rule Win_Adware_Maper_1
{
strings:
	$a0 = { 5c006c0069006e006b002e007400780074 }
	$a1 = { 69006f006e005c00520075006e00000d6d00610070007000650072 }

condition:
	$a0 and $a1
}

        
