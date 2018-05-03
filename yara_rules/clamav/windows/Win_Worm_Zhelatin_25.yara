rule Win_Worm_Zhelatin_25
{
strings:
	$a0 = { bb6d62400081e9a15500004a8d450881c6632800004aba }
	$a1 = { 8d0d7046243f2335387a2a356d }

condition:
	$a0 and $a1
}

        
