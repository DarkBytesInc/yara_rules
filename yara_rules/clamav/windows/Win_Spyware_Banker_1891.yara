rule Win_Spyware_Banker_1891
{
strings:
	$a0 = { b10498bd79caf27da3aa276abd3e2659b420bf2ea1996b8ae7bb85a94541bdb002afbd952ac08781ec4033d9ceb011cdcb2cef3345ed40589dd28e559257d62d99c6a8f174a4cdfe1043f0e39a72f88059b1db3198cbacfbb77e2dcf3d7637689a588e81781d581270ecd6223715436af8ec9c8b7dbec463864f90a596696c7e073a84a51384669fb1a5e8eef841e5c1152705e1 }

condition:
	$a0
}

        