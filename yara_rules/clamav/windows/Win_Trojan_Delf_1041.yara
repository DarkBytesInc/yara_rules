rule Win_Trojan_Delf_1041
{
strings:
	$a0 = { d29b515f3a1f995d26af299fdd2059d4a1ad0f72ad9675853fdf3dab0ae918bf1549bc959a300024be0e7ddd0bce27fb23c543c485ea23c7a92486f6054fed1fe02864653cb47edb3fdf6c86808c5b6a86a5a99094e19c0270 }

condition:
	$a0
}

        
