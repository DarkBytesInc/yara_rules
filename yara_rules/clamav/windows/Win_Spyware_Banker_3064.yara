rule Win_Spyware_Banker_3064
{
strings:
	$a0 = { 3f3a600b83f9e645d536e18330ca599a1e01617501dfaa8c8742a4fba9ee4b4a14508c9793ee9a350c58922862f870560a1e183826e97347bc95ca45c234 }

condition:
	$a0
}

        
