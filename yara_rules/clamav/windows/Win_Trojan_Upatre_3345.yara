rule Win_Trojan_Upatre_3345
{
strings:
	$a0 = { e978050000350c74908d8945dce8f10b0000535ae9ac0300008b4424048b4c24088b54240cff742410525150e8e31e0000c21000b900000201c1c90c8bb57cffffffc1c60d03cec1c906894de0e85a070000535ac3bf758abd7481ef758abe74e9dc0d0000e8250d00005659e8570600005359e8210100005359e8fd01000053 }

condition:
	$a0
}

        