rule Win_Trojan_Fakeav_46
{
strings:
	$a0 = { 446566656e73652043656e74657200005c000000646566636e742e657865 }

condition:
	$a0
}

        
