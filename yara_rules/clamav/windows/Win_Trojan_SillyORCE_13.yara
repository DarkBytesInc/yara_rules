rule Win_Trojan_SillyORCE_13
{
strings:
	$a0 = { 0526803d07741a9090be0001b94d00fcf3a48ed9be8400a5a5b82125ba4705cd2106c360b8013dcd2172159090931e0e1fb440ba0005b94d00cd21b43e }

condition:
	$a0
}

        
