rule Win_Trojan_Aimlog_2
{
strings:
	$a0 = { 8b9544ffffff52ff15fc1040008bd08d4da4ffd78d4d88ffd3566a018d45a4506a00ff15b410400056ff15a01040006a018b4da45168542640006a008b1d3c114000ffd38bf06a018b55a45268642640006a00ffd32bc60f800603000083e8040f80fd020000894590c74588030000008d45885083c6040f80e6020000568b4da451ff15901040008bd08d4da4ffd78d4d88ff151410 }

condition:
	$a0
}

        