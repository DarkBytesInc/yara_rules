rule Win_Trojan_IRC_Script_53
{
strings:
	$a0 = { 74696d6572666c6f6f6420243220247228332c352920636c6f6e652024332d200d0a202020207d }

condition:
	$a0
}

        
