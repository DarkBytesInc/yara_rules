rule Win_Trojan_SdBot_4431
{
strings:
	$a0 = { 817159a493446f8ed2ac55d60b211c5ddee68dd1523b7d547529c863a0712359e17ea4393a8675af9635124c29aba2b132233935ec1b8f06430b44434a213121d02e730c24bfd55ff45b402a28a7e78e1f2200be8cf2616c20172304ddb3cbc20c31847f5c3c1b6fb502c406f123e6abd08f6c18341680ec106b5a9a76958e667707730eb660fac12a81 }

condition:
	$a0
}

        