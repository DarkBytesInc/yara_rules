rule Win_Spyware_Banker_4522
{
strings:
	$a0 = { 56af5f806adf46e8f5cacd5b39498e8a5ca51a1f4d0c5ad9e9b2843c49a2fc61b26a9a6a753726e7d4499ada9a6b855f16ea3bdd0fc8a0c710cbe183ff85772627a248aebc0292235e2ac1f8307f8304fbf3660af9c380c181c4be8d333b22aab6e53bb0 }

condition:
	$a0
}

        
