rule Win_Trojan_Lowzones_16
{
strings:
	$a0 = { 4e4d542e45584522973b7420802800e5000000f503000002b891afc0d20eef301d33080020000000726531312e5245470814d50ccfdd137d0bc1f07c029f72bae0409a292b0b4838431c7196dca4191e373018f19998c64ef709990724c616166aa4 }

condition:
	$a0
}

        