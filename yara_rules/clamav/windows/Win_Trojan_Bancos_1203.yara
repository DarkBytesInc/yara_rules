rule Win_Trojan_Bancos_1203
{
strings:
	$a0 = { 208c4bb717c30306c1635c363ddd1a8423a52b294891403f1969320e8c0072bfa1e5f6162280d0e732c5918f91a20188dc451f340b2bd7290739d08e3a1a08019e1e0ef4f9e6e7405c1b5ac5e718fe7f7caa4e5790b49e79892ec8bda4c16b }

condition:
	$a0
}

        