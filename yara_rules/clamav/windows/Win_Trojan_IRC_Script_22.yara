rule Win_Trojan_IRC_Script_22
{
strings:
	$a0 = { 666c6f6f64 }
	$a1 = { 736f636b7772697465202d6e20636c6f6e652a20707269766d736720242431203a20242b2024636872283129 }

condition:
	$a0 and $a1
}

        
