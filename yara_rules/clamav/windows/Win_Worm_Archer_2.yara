rule Win_Worm_Archer_2
{
strings:
	$a0 = { 5c57696e646f77735c43757272656e7456657273696f6e5c52756e[0-75]5c41726368697665722e657865 }

condition:
	$a0
}

        