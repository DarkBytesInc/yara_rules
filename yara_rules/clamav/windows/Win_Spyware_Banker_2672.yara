rule Win_Spyware_Banker_2672
{
strings:
	$a0 = { 81e6557c965fe3dc7ced113c9c1a68185083403315078404e7b29a9f89230a74fb77b0d1aabac9f5cc4ddd1adc7b184529ecf1553bad429aad3d5d17263f9e610d844a1eee5c8f6d60a01b1ce3647cfba94e9b5c85d04166742786accdecd54956a8 }

condition:
	$a0
}

        
