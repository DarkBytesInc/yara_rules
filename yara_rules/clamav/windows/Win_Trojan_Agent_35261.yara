rule Win_Trojan_Agent_35261
{
strings:
	$a0 = { 19f283dad0a4369e70af6b1d66d562a2cb79a6ee51a3067628345f55b7a867a3e10aa24a0a71cd950f7b6977f258e710ee79d7776931cbf58a73af771d5c0c43c6cabfbbd5fd660c55e93efb3fff87dd84448d3ac0bebde52158 }

condition:
	$a0
}

        
