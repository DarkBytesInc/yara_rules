rule Win_Trojan_Agent_35263
{
strings:
	$a0 = { c19df3f300f47b136a111ff519f283dad0a4369e70af6b1d66d562a2cb79a6ee51a3067628345f55b7a867a3e10aa24a0a71cd950f7b6977f258e710ee79d7776931cbf58a73af771d5c0c43c6cabfbbd5fd660c55e93efb3fff }

condition:
	$a0
}

        
