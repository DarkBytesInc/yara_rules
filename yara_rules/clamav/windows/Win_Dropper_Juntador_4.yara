rule Win_Dropper_Juntador_4
{
strings:
	$a0 = { 8b423d1e5357180784bc01803bc395135fdfb8ad69f9579592f5aa6cd4d04153566584bbc223afb42cc8d417894848112a5c28091245b62b7ab7c83059f0 }

condition:
	$a0
}

        
