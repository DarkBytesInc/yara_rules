rule Win_Trojan_FM_1
{
strings:
	$a0 = { 83e90081e9200180c40088c0268a02346483ea002688020500004688d289c0e2e980c50080c400c3 }

condition:
	$a0
}

        
