rule Win_Adware_WhenU_3
{
strings:
	$a0 = { 340000000d00000000000000176e7349537570706f72747300495768656e555f }

condition:
	$a0
}

        
