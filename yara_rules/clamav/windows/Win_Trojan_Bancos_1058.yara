rule Win_Trojan_Bancos_1058
{
strings:
	$a0 = { 8a20e5efa8b50ebc8969240a67ad65760292f2c178efdae6b5a9338d851199447f9bcb1ca3ff32badb4b80523eca5e4d65c00a24c1dd3aa12bd264cbd0ffdf8e6bb6cfafda85493ea90d377b72f1a05b1ec8531e129ff2ab }

condition:
	$a0
}

        
