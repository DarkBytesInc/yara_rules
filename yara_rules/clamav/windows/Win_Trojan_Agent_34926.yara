rule Win_Trojan_Agent_34926
{
strings:
	$a0 = { 3b0ac220e81a8ad61c65aeb83868ef95e4e1b869716ba6b16d4cd8b73b7baea6367eede687867fbb7d3cbda11063176bef6010f4ec04cc92154ac195336c7f0672b11b993d67dfa24849b1b76c31ae5d54e9b6c516635cffc036 }

condition:
	$a0
}

        
