rule Win_Worm_Fujack_30
{
strings:
	$a0 = { d888336f10c4db7a28d0f83f86f103d4da68af56102ac314c568b37a729b1239cce8ecfa84f10c94467a3dc410fa779e207bc8432378817e564564516e45f87085b65962d875095f18df6afe9b2709c6756da708ab6e885e7078b4c68b16baba0f23a4bc485d5517b26fcf457c89248e3b60752370322e88777f761d2f637c8730363b7b07ad65ffa775601efe8f6c6e }

condition:
	$a0
}

        