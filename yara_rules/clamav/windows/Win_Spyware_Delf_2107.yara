rule Win_Spyware_Delf_2107
{
strings:
	$a0 = { 5ca5eb5a175d4235a85c96881134a8fbe441471efb2aebf955c3a74bf9907ba17131920e43530c2fc527a341f06a443868d11d85fbf449fe911d9e979bf602499423c5d23705716b7b7f73bd833dd06a3b13a62fbc1944fb5e7370b08f7713fb93e052ea59d3fc83a9cb78cd82fed476127d217abe0b11c850097a77b5d99db4affd48fc65b047151fa94024 }

condition:
	$a0
}

        