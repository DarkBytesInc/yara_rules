rule Doc_Trojan_Neuro_2
{
strings:
	$a0 = { 496620282e4974656d2853596172444c5177466c292e4e616d65203d2022415650204d6f6e69746f722229204f7220282e4974656d2853596172444c5177466c292e4e616d65203d20224e41495f56535f535441542229205468656e202e4974656d2853596172444c5177466c292e436c6f7365 }

condition:
	$a0
}

        