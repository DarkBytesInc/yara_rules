rule Win_Trojan_Devious_1
{
strings:
	$a0 = { 49662066203c3e20223c68746d6c3e3c212d2d48544d4c2f446576696f7573202e612d2d3e22205468656e }

condition:
	$a0
}

        
