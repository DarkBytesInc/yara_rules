rule Win_Trojan_Small_4541
{
strings:
	$a0 = { 56648b403085c0780c8b400c8b701cad8b4008eb098b40348d407c8b403c5ec3 }
	$a1 = { 48745f48744d48743c48742a }

condition:
	$a0 and $a1
}

        
