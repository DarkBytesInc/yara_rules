rule Win_Trojan_Clicker_34
{
strings:
	$a0 = { 6966202877696e646f772e73796d7265616c77696e6f70656e297b77696e646f772e6f70656e203d2073796d7265616c77696e6f70656e3b7d206966202877696e646f772e6e735f61637475616c6f70656e29207b77696e646f772e6f70656e203d206e735f61637475616c6f70656e3b7d2069662028747970656f66287573696e67636c69636b }

condition:
	$a0
}

        