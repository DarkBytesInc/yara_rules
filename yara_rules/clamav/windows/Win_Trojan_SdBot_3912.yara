rule Win_Trojan_SdBot_3912
{
strings:
	$a0 = { daf3afe03ceae934b0e22300b32312f3306fc018d6ddbd62211c2925a2eb8af1ecf74a5ff8a4b3e90a3a6f04faf6766d32b8b6e922aeea1b1272e416385db27420caeb29bb94cbf8c128821808250f0e342cf58c9f89534b376d7977 }

condition:
	$a0
}

        
