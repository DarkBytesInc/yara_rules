rule Win_Worm_Trilissa_2
{
strings:
	$a0 = { 0a40666f726d617420??3a202f75202f6175746f746573740d0a40666f726d6174 }

condition:
	$a0
}

        
