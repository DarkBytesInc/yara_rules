rule Win_Worm_VB_895
{
strings:
	$a0 = { 8c009d9d9d9d986028449d9d9d9d949034089d9d9d9d88409c649d9d9d9d187074509d9d9d9d1484483020169e9d3c80682c13e887c5c10c010001d53000806a46c289cf6d638d064d92f61eead0162eae1618cf120117cb0200dcae1d0050726f6a6563743100ad070070169fffcc000f85ea766a23fe4a000000008a19a91062708fff04c647bfc55b1b43 }

condition:
	$a0
}

        