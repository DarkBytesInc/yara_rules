rule Win_Trojan_Small_4536
{
strings:
	$a0 = { 648b403085c0780c8b400c8b701cad8b4008eb098b40348d407c8b403c5ec3 }
	$a1 = { 48747648746448745348744148742f48740733 }

condition:
	$a0 and $a1
}

        
