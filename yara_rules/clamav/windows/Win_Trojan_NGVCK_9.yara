rule Win_Trojan_NGVCK_9
{
strings:
	$a0 = { e80600000000295f00008c812c24052040005d4583ed017421baf50b0000be3a20400003f58a1e029d052040 }

condition:
	$a0
}

        
