rule Win_Trojan_Small_497
{
strings:
	$a0 = { 50494e4700707269766d7367006b69636b000d0a003a25455800003a255550 }
	$a1 = { 45e08b15cc2240000fbe0402898524fdffff83f843740d7c3b83bd24fdffff4f741deb30ffb5bcfeffffff15401640006a0068c6004000ff154c164000eb6b6a0068d1004000ff15381640008985bcfeffffeb56837dc80075188b45e08b15cc2240000fbe04028d409f8985b8feffffeb358b85b8feff }

condition:
	$a0 and $a1
}

        