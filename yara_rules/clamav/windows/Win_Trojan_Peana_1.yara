rule Win_Trojan_Peana_1
{
strings:
	$a0 = { ffffff20202020205b5045525349414e412049495d20202020ffffffbe6e114000b99907000080362346e2fa6a3268761640006a00e8610900000bc00f84be000000686e11400068ea164000e83e090000a36e164000400f84a3000000a19a1140003d6578706c746f3d70726f6774683d656d6d3374613d72756e64 }

condition:
	$a0
}

        