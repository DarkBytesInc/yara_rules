rule Win_Trojan_Fraudload_15
{
strings:
	$a0 = { faaffeffb1f3b8fe49f38482fa610cff439f0ffffa6d0cb6fad9fe99faffc9feb1f3db436b630cff6184fe4f4380fefffab9fe8a539a98a76f600c92faa2feff52aafe8a66f3ffff3cf3a8fe43a3fefffaffff44faff908259f3ffff72a1affeb57cff88 }

condition:
	$a0
}

        
