rule Win_Worm_Opanki_4
{
strings:
	$a0 = { 400033f656ffd385c075b75f5e5d5bc35356578b3dfc20400033db53685c3240005353ff15ec2040008bf056ffd785c07417ff74241056e82affffff595953536a1056ff150021400068a00f0000ff153c20400056ffd785c075c05f5e5bc383ec0c5355568b35ec20400033ed5755680c32400055ff74242cffd655686c3240005550ffd68bf857ff15fc20400085c00f8414010000 }

condition:
	$a0
}

        