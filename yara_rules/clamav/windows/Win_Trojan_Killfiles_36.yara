rule Win_Trojan_Killfiles_36
{
strings:
	$a0 = { 406563686f206f66660d0a0d0a3a73746172740d0a7469746c65204469736b204b696c6c6572 }
	$a1 = { 726d646972202f53202f5120433a5c }

condition:
	$a0 and $a1
}

        
