rule Win_Trojan_Lowzones_50
{
strings:
	$a0 = { 68e4304000ff15302040008945d08b4dd0894dccc745fc0000000083ec108bcc8965e88d55e45268c8304000ff1530204000 }

condition:
	$a0
}

        
