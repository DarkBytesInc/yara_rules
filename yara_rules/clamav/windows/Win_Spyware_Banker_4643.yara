rule Win_Spyware_Banker_4643
{
strings:
	$a0 = { e146f1785548c0107547931e8fa7e0c13a7af8c7402e3ff8764e8cf1ae19de2e0eecd5dc8e903aeea5904e30d5bb5acdd973276c9d21dd55a1bfe22b0beae9f692072b5cba7e2d1edbd19169a75ef1749580b1ab6a2ece5ebaa13d0484e31b175b2a320992eba8dc45ff46b8bb4ae60b26ed35004117 }

condition:
	$a0
}

        
