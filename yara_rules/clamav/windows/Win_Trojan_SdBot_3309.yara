rule Win_Trojan_SdBot_3309
{
strings:
	$a0 = { 8ea4efabdbe58f2183f1d6de2e2a0c349bd2858be4e77106acd142eea608dd8db300c1cc24db9c6a323acb8c4adc8e386486313940e4ea97dec663e32a8ccdebfa35f65e9792f417a1d9a7a4f32e66fad388c0e487f4d1181539a261568918c6bd7c8cee419e06dc9ecb1783311a6bc902955de417b25ad9dfe3617c3b3e93622dc5b47fbef8bf808d93f2035fbc }

condition:
	$a0
}

        