rule Win_Spyware_Banker_3334
{
strings:
	$a0 = { f02ff727ba7abfdb772212fa6b117046e45cf31089232d6c4326b075215fd00b9be6bc5be68c6f9cc3e98619d37511f07c895a0f0da148f65bce2cd95c8c555bb65ca6ffc4a35452b89099594f8c0a0c1836e08d27 }

condition:
	$a0
}

        
