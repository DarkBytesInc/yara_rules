rule Win_Trojan_Soupy_1
{
strings:
	$a0 = { 01b9120281340000ade2f9e800005d81ed130133c08ed8c40690002e8c866b052e898669058d96f002891690008c }

condition:
	$a0
}

        
