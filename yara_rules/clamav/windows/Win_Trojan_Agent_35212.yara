rule Win_Trojan_Agent_35212
{
strings:
	$a0 = { 4d48df2cd471f32bbee9bec1245701355b443844b515315d5a8fda4116b7b2dba939f908e6fa5051df41558a9ff6322a10fca89e5cc7962bc9809dd0fa46b466f4bd1829f2985c36e02ead6e366f }

condition:
	$a0
}

        
