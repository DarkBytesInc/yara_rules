rule Win_Trojan_Agent_35596
{
strings:
	$a0 = { 12117a31cbdd3619670000ee37cad451da079072229cd7 }
	$a1 = { 634b6579546f6b65013d35393562363431008034346363 }

condition:
	$a0 and $a1
}

        
