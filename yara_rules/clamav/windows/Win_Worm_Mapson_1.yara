rule Win_Worm_Mapson_1
{
strings:
	$a0 = { 8eed3e4807db1923fc00f0dab3807c2e9847d618d802c0d24c07019f38aa2a020732ccde89d2138b0d07001607cbf73a7101375c2127ec2260fdffff9b26cbcc }

condition:
	$a0
}

        
