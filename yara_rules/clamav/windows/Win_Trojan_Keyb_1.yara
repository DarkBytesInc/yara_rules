rule Win_Trojan_Keyb_1
{
strings:
	$a0 = { 0400b440cd218d960801b92601b440cd21b800429933c9cd218b8652024089860501c6860401e9 }

condition:
	$a0
}

        
