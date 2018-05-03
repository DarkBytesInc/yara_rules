rule Osx_Keylogger_Logkext_1
{
strings:
	$a0 = { 7c0802a6bfa1fff47c7d1b78900100089421ffb0480000313c400000382100507fa3eb7838421610 }

condition:
	$a0
}

        
