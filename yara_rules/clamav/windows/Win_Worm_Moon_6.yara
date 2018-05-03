rule Win_Worm_Moon_6
{
strings:
	$a0 = { 66696c65636f70792022633a5c6e6f6f6d6d2e6f6474222c2022633a5c74657374312e6f647422 }

condition:
	$a0
}

        
