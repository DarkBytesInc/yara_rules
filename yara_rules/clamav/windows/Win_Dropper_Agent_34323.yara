rule Win_Dropper_Agent_34323
{
strings:
	$a0 = { 535633f633db56ff152c80????397424107e44578b7c241085db751666813c3e????752b66817c3e02??????226a015beb0b813c3e????????750733db83c603eb0d8a043e50e8??a2ffff5988043e463b7424147cc25f }

condition:
	$a0
}

        
