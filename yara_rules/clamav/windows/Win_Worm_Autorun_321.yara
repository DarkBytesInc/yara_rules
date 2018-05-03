rule Win_Worm_Autorun_321
{
strings:
	$a0 = { 6175746f2e657865[0-84]7368656c6c5c6f70656e5c436f6d6d616e64 }
	$a1 = { 41764d6f6e69746f722e657865 }
	$a2 = { 6d79646f776e }

condition:
	$a0 and $a1 and $a2
}

        
