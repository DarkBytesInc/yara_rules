rule Win_Trojan_Nymaim_5504004_0
{
strings:
	$a0 = { 8b7d??ffb2b40000008f87b4000000ffb2c40000008f87c4000000[7]ffb2a00000008f87a0000000ffb2b80000008f87b8000000 }

condition:
	$a0
}

        
