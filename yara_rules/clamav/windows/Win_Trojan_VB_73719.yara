rule Win_Trojan_VB_73719
{
strings:
	$a0 = { ff25b0104000ff252011400068a81b4000e8f0ffffff0000580000003000000050000000380000008f396c9a2dbeb14cb895a9285548c4a2000000000000010000000000000000007461737369005c6f796f616e6470 }

condition:
	$a0
}

        