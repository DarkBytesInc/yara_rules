rule Osx_Trojan_Jacksbot_1
{
strings:
	$a0 = { 692e6a6172206d61696e2d636c6173733a20636f6d2e726564706f6973306e2e70 }

condition:
	$a0
}

        
