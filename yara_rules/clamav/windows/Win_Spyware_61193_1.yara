rule Win_Spyware_61193_1
{
strings:
	$a0 = { 68080200008d84244c0100006a0050e89317000083c4188d4c24385168080200008d94244401000052689041002568884100256880410025ffd38d84243c010000689041002550be02000000ffd583c40885c00f84bf000000 }

condition:
	$a0
}

        