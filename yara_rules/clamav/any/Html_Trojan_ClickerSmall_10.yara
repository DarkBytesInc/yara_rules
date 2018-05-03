rule Html_Trojan_ClickerSmall_10
{
strings:
	$a0 = { ec576d792d69242e53666fd52602e1136bb91a208cad363b6f277311b6e4c67c62043b685f5f11f24f6d697261636c6565757097dbdf6d5c635b32 }

condition:
	$a0
}

        
