rule Win_Trojan_Bancos_649
{
strings:
	$a0 = { 6ea575f88825aa6deec91765b12e1728433c02d44499e08b60537587f161b3c52f035d98f1e03a14e4b80365a1ad4281fd4fea05e4ca8b4cae176f1d386d112c5ff6722e }

condition:
	$a0
}

        
