rule Win_Trojan_Mybot_8425
{
strings:
	$a0 = { f92494a87c7e245b377c84acbb331403590f318bc2b5c5b3b2fd102355e235cac1fac4547ba3427b4d129c051e65767b32daf10c9b9eccb1de65e743729f8a243e80bfcebfca3ab6591345d3c7ff3f9fa4c829cd8e }

condition:
	$a0
}

        
