rule Win_Trojan_IRC_Script_132
{
strings:
	$a0 = { 616c69617320686964656e73207b2072756e20[0-8]2e657865202f6e202f6668202f722024312d207d }

condition:
	$a0
}

        
