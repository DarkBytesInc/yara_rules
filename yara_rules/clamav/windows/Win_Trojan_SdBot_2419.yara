rule Win_Trojan_SdBot_2419
{
strings:
	$a0 = { b66ddbb66ddbb66ddbb66ddbb66dfbffce39ffbd6bddac369849da274d9ba499490201f07f86abdf19282048e5ff1c25ae0967c06e55aec5ff02216ae7ffcbdf7206ecd5895a09b8b9e6e407e03afe8f134695f2c3c50f107049fd1fdfbf879d9b1f00c0193d2a04e73f0f7008d97ff6 }

condition:
	$a0
}

        
