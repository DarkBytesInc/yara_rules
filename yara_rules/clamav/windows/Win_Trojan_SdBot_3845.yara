rule Win_Trojan_SdBot_3845
{
strings:
	$a0 = { c9b66c2451e2c46cb12e24b507f2b9645faeed539f411e3b4197af400588450c1810f20532ffc7d05c81fddfd6dd53d4aab0aebfb81eecd811bda9792ee238e41b1b6dd702ced288c057678e60f22af60c2d615dfd81da8a7da7237c759f5a37bd10 }

condition:
	$a0
}

        
