rule Win_Trojan_GWGirl_1
{
strings:
	$a0 = { 2e636f6d000000004458496e7075742e646c6c00473268376f3273745f4576656e7400005c5343414e524547572e455845 }

condition:
	$a0
}

        