rule Win_Spyware_Delf_633
{
strings:
	$a0 = { 113ba7bef0da98f9e9ba3dae7e168cc2b4f77f8e4d215b71af2c4a1c0734e56b5fabca488f343ca0c0b25b1bfd9d7c229057503f1c0c5f81710f19eedef2b0a06a6163032d30cfc6278f83126e77588ecb4cb99aa7ed6f443e5e188009ebf4285af3314ee9c4bf3494f3b673c00a36e4928a7775e9a55c5201a53c4da02bf163156a90411bbb1720e365e927d6881061b5c5e19ca2e8 }

condition:
	$a0
}

        