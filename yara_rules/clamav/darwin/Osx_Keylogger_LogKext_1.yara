rule Osx_Keylogger_LogKext_1
{
strings:
	$a0 = { 6c6f674b6578744461656d6f6e }
	$a1 = { 6f674b657874436c69656e74004572 }

condition:
	$a0 and $a1
}

        
