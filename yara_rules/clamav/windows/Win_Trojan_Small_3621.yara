rule Win_Trojan_Small_3621
{
strings:
	$a0 = { 42b2edca4dc55e4564548c0c66c88fe99e0ff7ba50f9982813464fc3369dc1330b059fe5539ba1cc2ff44baa938f317c5e39daeec1b07d380060e5bdd9a081901c36c643f2683bd0b13acb7ac0e312c0e2df0f9dd0883f06e385 }

condition:
	$a0
}

        
