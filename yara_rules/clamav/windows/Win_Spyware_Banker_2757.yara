rule Win_Spyware_Banker_2757
{
strings:
	$a0 = { 93f88a30feeae758cfa787a741f66d2fbcff55c97c3cf56a2ea100deb07f262736ac648b120e1cad3dafe5c4e7f54931e64a2ace71bc2efad780807062c702eb9e81855cd2b036db7b0fa11b010bb6584b4f937a35e527f7f0d0c7a1457d36f26832d517 }

condition:
	$a0
}

        
