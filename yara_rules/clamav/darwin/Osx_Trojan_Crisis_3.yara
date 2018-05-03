rule Osx_Trojan_Crisis_3
{
strings:
	$a0 = { 2f746d702f343374393930337a7a252e38642e58585858 }

condition:
	$a0
}

        
