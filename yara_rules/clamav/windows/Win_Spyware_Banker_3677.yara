rule Win_Spyware_Banker_3677
{
strings:
	$a0 = { 9c5c1a0d7623d0b7888367adec1c00af1bae8be0edfb9400ec21040ce756c02000d8a4d46ee3f5ed537cda0034701583b0dc5e3d3d604a808edec5b1ae3301018561d20d41695cddefefd08a47773ecba1801fc8cfbb4b14b17083f8f7006810588fdac92a77002119b96ef34666a800a17bab5cbb3d1b2d39996f3cb000d74036c50d3c8803098751a3b1a2 }

condition:
	$a0
}

        