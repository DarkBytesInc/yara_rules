rule Win_Dropper_Agent_33522
{
strings:
	$a0 = { ce7a0d5553119c61e63d73c9bbafade1ccf1e0c3dd4fc478d24690b77192e7122ef22abeae9ff0ae6a43551fa4da8d7dcf2ab88cd8d5d5c8996533b21dc58539588d1d5936ca1a0fa6a127b11416079bacf0e106 }

condition:
	$a0
}

        
