rule Win_Trojan_Agent_33332
{
strings:
	$a0 = { 1ca05387eef884b19d5d72205f929fa4832a7c88af8d5e489f00e23e3b4f830cbf1976f708de204d06c972c1133146fbe46a1b30e5937142bd13cf7c417bb930d400dac30a69f21acf4c292b36cc3c04eba06f6f1c1acb64bcf3a2aac726 }

condition:
	$a0
}

        
