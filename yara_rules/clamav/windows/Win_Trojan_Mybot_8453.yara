rule Win_Trojan_Mybot_8453
{
strings:
	$a0 = { 8cb1d4d56055b311c13bc1ddc239aedca4a6a729ad11d82c9caeafac36badac13530b7b4b502a83c3dbebfbce516f605898bb40884858889d1f6bcf0407273701a9e98853c619e989947c630aa82838052c2902b58 }

condition:
	$a0
}

        
