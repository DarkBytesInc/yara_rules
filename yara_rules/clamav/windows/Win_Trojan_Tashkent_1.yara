rule Win_Trojan_Tashkent_1
{
strings:
	$a0 = { 2a2e434f4d0092a0e8aaa5ade2289129203931a300eb599041424344e96100640164010a0143448c973282f0f3 }

condition:
	$a0
}

        
