rule Win_Spyware_TinyK_1
{
strings:
	$a0 = { 776172655c54694b4c000000496e7374616c6c446972000025732e646c6c000025732e6578650000556e61626c6520746f206c61756e63682054696e79204b657920 }

condition:
	$a0
}

        