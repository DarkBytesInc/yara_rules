rule Win_Spyware_Banker_2998
{
strings:
	$a0 = { 93d71474396aa776fd1eaaa448247a86c2b0cec790b39e4690a17160490271136debac68b38018592616c3756318e0a1ebf81bf6da677ccf5c2540b4acdb408ba3e49631 }

condition:
	$a0
}

        
