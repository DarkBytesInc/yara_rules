rule Win_Trojan_Androm_1
{
strings:
	$a0 = { ba59540000558bec81ec14020000812526814000368140006804010000c7051e774000e31500008d85ecfdffffc745fc }

condition:
	$a0
}

        
