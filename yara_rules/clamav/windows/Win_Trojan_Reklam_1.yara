rule Win_Trojan_Reklam_1
{
strings:
	$a0 = { 3d72656b6c616d6179 }
	$a1 = { 6966202573617969203d3d3d2030207b202e736574202572656b6c616d202572656b6c616d30 }

condition:
	$a0 and $a1
}

        
