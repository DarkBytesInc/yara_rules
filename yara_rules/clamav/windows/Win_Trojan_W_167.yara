rule Win_Trojan_W_167
{
strings:
	$a0 = { 0202b23a1587a24d81137b921a20de6351bcce76b79dee7787e1cfc07bf940b6f7225e7a40e5f4815b5dc1b5240ad7720ac802db920b5c80dae485f4c835eb9b05ae48bc5c905b72036b920f2dc83cb7b9016dc1bce72e05b9db96f73bcefe3dffffff5bbf3e79e79f7ef9ad7dfb }

condition:
	$a0
}

        
