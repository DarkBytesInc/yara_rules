rule Win_Spyware_11332_1
{
strings:
	$a0 = { 74019061807ff04590600f851b8b1fff683d8a4000b800104000903d00b44000740680303a40ebf3c3 }

condition:
	$a0
}

        
