rule Win_Trojan_Small_5228
{
strings:
	$a0 = { 78d21c87526f919cb22d20fbc3a31acca8b5229ce9ca29e12c55f21114031af6ac7646424c08bed01157f917347acdcf71bafeeab1524ccb0262abe1375b7504c39ad5da1008fd881f3f15b1317461c8d304f611adeaae910b23cc9cd18913c951204b4945df907c2e6460394c79426e0aa422c050b53e1a74470ceb99643d8d7bef }

condition:
	$a0
}

        