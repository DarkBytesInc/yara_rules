rule Win_Worm_Stration_428
{
strings:
	$a0 = { 78f331a5ba432bb67b9c7a50da2a2d3fce80ee8afe604e9a8d4938d46d98d7a2aca294465b593e59720002c44344451b8c1fde67511c0c8f116f3c2a6dbbcc5889e9ffd88140519071a2ba26c3938a48 }

condition:
	$a0
}

        
