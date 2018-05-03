rule Win_Proxy_Lager_75
{
strings:
	$a0 = { c46a0ab3e4dd645729411e1878616ab4646708bb12cff0b8788fa22afb57efa89c622768c26f09c3c46a77aaf8656fdd3bb84bd64018b2a92348ffec2567105faf1e9f33d608 }

condition:
	$a0
}

        
