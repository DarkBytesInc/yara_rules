rule Win_Trojan_Realplay_1
{
strings:
	$a0 = { 7768696c65287265616c7a685b226c656e677468225d3c74656d70297265616c7a682b3d22686f686f686f22 }

condition:
	$a0
}

        
