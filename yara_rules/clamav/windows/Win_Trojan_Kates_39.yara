rule Win_Trojan_Kates_39
{
strings:
	$a0 = { 01c0d1e8c38d4000c38d40009090c390558bec33c055683510400064ff30648920ff050070400033c05a5959648910683c104000c3e9ceffffffebf85dc38bc0832d0070400001c3558bec33c055686d10400064ff30648920ff050470400033c05a59596489106874104000c3e996ffffffebf85dc38bc0832d0470400001c3ff25449040008bc0ff25409040008bc0ff253c9040008bc0ff25509040008bc0ff254c9040008bc0558bec33c05568cd10400064ff30648920ff050870400033c05a595964891068d4104000c3e936ffffffebf85dc38bc0832d0870400001c390908edddd93de22c8df2eb1afcbfed2b03b237e04cbc198731ff2a0d487e9910c7fd665cc33144f66239c61091786f30f96c2e63aa0594524d3f23450e8cd8bb4e1a8281c560439aadc167de44bec9077b0e330dcf7ae07ef8a0d9e6838eb767b238d5d8d2d0c4a5eaff7838586a306f906e198 }

condition:
	$a0
}

        