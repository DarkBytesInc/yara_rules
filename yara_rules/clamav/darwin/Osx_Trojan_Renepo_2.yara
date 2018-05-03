rule Osx_Trojan_Renepo_2
{
strings:
	$a0 = { 6f7378726b203a206f732078202d20726f6f6b69742023 }
	$a1 = { 75706974656d732f6f70656e65722f6f70656e6572 }

condition:
	$a0 and $a1
}

        
