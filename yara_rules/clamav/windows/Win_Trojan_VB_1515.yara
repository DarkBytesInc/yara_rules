rule Win_Trojan_VB_1515
{
strings:
	$a0 = { 666f6e797865006c6700006a6c00000001000700e42d400000000000eca84200ffffffff00000000882f40 }

condition:
	$a0
}

        
