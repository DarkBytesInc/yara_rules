rule Win_Worm_F_36
{
strings:
	$a0 = { 11219b2dcffcae01300727d88b00b6c04f7364ebb69434ddb027703002100000fedcbc7ced7518020009000000ff }

condition:
	$a0
}

        
