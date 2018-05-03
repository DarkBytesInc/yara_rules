rule Html_Trojan_ClickerSmall_88
{
strings:
	$a0 = { 6a00e8000001e0a394344000e8000001daa3903440006a036a006a00684a34400068453440006a00e80000021c }

condition:
	$a0
}

        
