rule Win_Trojan_Haxdoor_113
{
strings:
	$a0 = { 6774682931301d73697a651361716ff7bddbfba76d703b74226f6666f9209f6d6745fe06fcdf72631f68747470733a2f2f3c652d676f6c642ece7e9bd0582f2c }

condition:
	$a0
}

        
