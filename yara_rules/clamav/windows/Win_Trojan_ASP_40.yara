rule Win_Trojan_ASP_40
{
strings:
	$a0 = { 222f6322267462636d642e74657874 }
	$a1 = { 64656c66696c652874656d7026786469722e6e616d6526225c2229 }

condition:
	$a0 and $a1
}

        
