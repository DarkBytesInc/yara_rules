rule Win_Spyware_Banker_2364
{
strings:
	$a0 = { b8bee4cf5aeffe815fa9f3045f30dc7e66deff87c3fda1cab29dbc86e1d1543fc644b8aa5755aebb156a560e133830108de4f985706e4cdcf9c4b956681d4cb2b64f0873246feb5ddb03298ac4a2226526884641542f1de1283ec3c67f3bbaacb7bc953e2811 }

condition:
	$a0
}

        
