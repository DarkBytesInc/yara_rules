rule Win_Trojan_SdBot_2316
{
strings:
	$a0 = { cccccccccccccccccccccccc558bec6a016a016a00e81200000083c40c5dc3cccccccccccccccccccccccccc558bec51e8e7000000833ddcdb47000175118b450850ff15a403480050ff1588034800c705d8db4700 }

condition:
	$a0
}

        
