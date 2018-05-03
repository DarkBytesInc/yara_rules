rule Win_Worm_Blaxe_1
{
strings:
	$a0 = { a6699abebfbfbfc0c0699aa669c0c1c1c2c2a6699aa6c2c3c3c4c49a65679ac4c5030dc671d59a65b36c39c79d01c865c9ba4db36c2dc991f559caffca699aa669cbcbcbcccc9d699aa6cdcdcdce0309b2699a93cf677bdf43d0b26996cda70bd16fd337d2b25936cd9bff63d3c72bd4b25936cd8ff357d5bb1fd6b259 }

condition:
	$a0
}

        
