rule Win_Trojan_CVE_2012_0507_5
{
strings:
	$a0 = { cafe(babe|d00d)00000030 }
	$a1 = { 41746f6d69635265666572656e63654172726179 }
	$a2 = { 436c6173734c6f61646572 }

condition:
	$a0 and $a1 and $a2
}

        
