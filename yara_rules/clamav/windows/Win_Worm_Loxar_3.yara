rule Win_Worm_Loxar_3
{
strings:
	$a0 = { 45207845524f7820774f524d2200000000b840af4100e832fbffffb854af4100e828fbffffb868af4100e81efbffffb87caf4100e814fbffffb894af4100e80afbff }

condition:
	$a0
}

        
