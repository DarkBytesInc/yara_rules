rule Win_Trojan_Casey_1
{
strings:
	$a0 = { 4361736579566964656f00000000000000000000ffcc31001453ab33636f6aed41af02c7e678e6ecc1c28a24313be2ba46ae306cfd7939e2bc3a4fad339966cf }

condition:
	$a0
}

        
