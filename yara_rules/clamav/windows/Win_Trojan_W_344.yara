rule Win_Trojan_W_344
{
strings:
	$a0 = { abc3cd2009008b04cf536578792e323030305f5747792490909090600f014c24fe618d58f066895f08b4ee }

condition:
	$a0
}

        
