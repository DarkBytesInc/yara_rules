rule Win_Trojan_Alliance_13
{
strings:
	$a0 = { 69084d61634e616d65240c6906466e616d6524076a093a4175746f4f70656e64 }
	$a1 = { 6756007363000c6a }
	$a2 = { 6f021d67238005060c086c01001e52646f0367c2806a0f476c6f62616c3a4175746f4f70656e1269084d61634e616d652464 }

condition:
	$a0 and $a1 and $a2
}

        