rule Win_Trojan_Agent_33320
{
strings:
	$a0 = { 73611f434eec73d47b478d4d48df2cd471f32bbee9bec1245701355b443844b515315d5a8fda4116b7b2dba939f908e6fa5051df41558a9ff6322a10fca89e5cc7962bc9809dd0fa46b466f4bd18 }

condition:
	$a0
}

        
