rule Win_Spyware_Banker_6227
{
strings:
	$a0 = { b2125ca5eb5a175d4235a85c96881134a8fbe441471efb2aebf955c3a74bf9907ba17131920e43530c2fc527a341f064da754330810ac60e166a27ebdcf9513551d4d69bd17832f9b3bbe14b09a2dbd5ee63be27108b2d3750a8c811697bb39f8f36c0cbdbd7ea34aed8a05777f8c0735fc28184f6461ee80a2ecf1fb36226303dc453ea3299ba3692eccaaf }

condition:
	$a0
}

        