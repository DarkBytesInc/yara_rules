rule Win_Trojan_SdBot_2198
{
strings:
	$a0 = { 69f81636e9a777075750d00300d259528eac502f5acdee0581550f3d20f9263710d981ba66b2c8fb16780065cfe829878500212c07e95f63002a98e16983f50cd0ac8236dcbeae009b8899a477fc07183f73e2933a4915a0cd0f91a9c00d43899bdf710faba23f28981b8d00d87010a189d24800e81d78a89b7e00dfb9904ea5af0165094a1782f750c43846c6880fd74da1 }

condition:
	$a0
}

        