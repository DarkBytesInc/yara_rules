rule Win_Spyware_Goldun_89
{
strings:
	$a0 = { 5168d2670210e89c0f00005b5f5ec36819310010e80a0f0000683231001050e8050f00006683388b75024040a317100010891dfe5b00105657e8000000005e81ee771f00108b7c24100bff7418803f007413813f677a69707508c70774657874eb0347ebe88b7c241c0bff0f847d01000081ff881300000f8f710100008bd68bcf8b3d855000108b742418ac497403aaebf9aa8b7c24 }

condition:
	$a0
}

        