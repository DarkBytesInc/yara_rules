rule Win_Downloader_103792_1
{
strings:
	$a0 = { 73646d2e63706c000000353038333538383333000000333437343831363034000000558bec83c4e8e80000199c893d04504000385d3c7d128d7c24ec8a54240c866424e88d05155040008d5c24e83b5dc47b0d8815075040008a7c24104f4f493a6424f87d08886c24f0867424fc3a7d0476 }

condition:
	$a0
}

        