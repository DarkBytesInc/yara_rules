rule Win_Worm_Magold_2
{
strings:
	$a0 = { 7461496d3e732ec38930af624d3804892e07d2602e438830e3f649d1c3232e0c04500b67b9321c }

condition:
	$a0
}

        
