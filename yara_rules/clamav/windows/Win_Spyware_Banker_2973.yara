rule Win_Spyware_Banker_2973
{
strings:
	$a0 = { 2d72b3f6a868330dffc8c620c6c220ffc6f185f405ca3fade1c52b847769fc3d963cb83f46cb62cc539fd6c4ba640f34e2335e83ed7eb01d0f9a71590fec950647cd7e074dd4e0b7694bfec8754b64322cd17e36bdb8f59dc76654fd5e02691f3ad3eb81 }

condition:
	$a0
}

        
