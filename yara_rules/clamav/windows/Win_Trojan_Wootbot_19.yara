rule Win_Trojan_Wootbot_19
{
strings:
	$a0 = { cd373bf179353f2deceffa13e3d3feebec9b5b44a10085159e7ba65b4173ae4206be9d1bec0213b7e4ef2bb405084c373aa498bf0a7eaea6b640db767bea8b37b2f1b6b0974d28c54542426009e0c216c479c27bf9c3e735503f2ec2df62ff4c7307df91c1e125b3250ed4995d6dd733ff5775b3abcc0fbae5de6ab736cf0a415e1b424662fd2c0b98540f553363ac404113ffe9 }

condition:
	$a0
}

        