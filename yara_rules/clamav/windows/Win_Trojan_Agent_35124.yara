rule Win_Trojan_Agent_35124
{
strings:
	$a0 = { 1feddddac2e5f815959897050835c34d80262ab87f0f4eeaeeb6850e7a6f86d848a2dca45427bbcf93eb1ccb11a6629c4de43160a8d3414795953aff1d03d4063d06f41c159a1bfb6430de2eaa56c995 }

condition:
	$a0
}

        
