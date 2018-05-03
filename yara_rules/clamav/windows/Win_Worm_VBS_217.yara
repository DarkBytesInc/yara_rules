rule Win_Worm_VBS_217
{
strings:
	$a0 = { 6372656174656f626a656374 }
	$a1 = { 226e6f69746163696c7070612e6b6f6f6c74756f22 }
	$a2 = { 2e6174746163686d656e74732e616464 }

condition:
	$a0 and $a1 and $a2
}

        
