rule Win_Trojan_N_64
{
strings:
	$a0 = { 770d5753ff951515400083f80075c053ff951915400081c40004000061c36080bd8c1740000f0f87a70100008bf2ac0ac075fb8b46fc3d45584500740b3d657865000f858b0100005268a08601006a00ff951d1540008985391540005ae8b4feffff83f8000f845001000093e8 }

condition:
	$a0
}

        