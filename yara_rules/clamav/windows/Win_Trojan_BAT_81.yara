rule Win_Trojan_BAT_81
{
strings:
	$a0 = { 64656c20633a5c6d79646f63757e315c2a2e7478742064656c20633a5c6d79646f63757e315c2a2e6d7033 }

condition:
	$a0
}

        
