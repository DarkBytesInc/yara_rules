rule Win_Trojan_JS_269
{
strings:
	$a0 = { 646c5f[0-16]6a70672f2c222e706870[0-32]76617278306365633231653266633d22363040255e37 }
	$a1 = { 74656d703d783063656332 }

condition:
	$a0 and $a1
}

        