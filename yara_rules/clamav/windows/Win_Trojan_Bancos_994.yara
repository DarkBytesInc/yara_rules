rule Win_Trojan_Bancos_994
{
strings:
	$a0 = { 3d926d6e2d1bb1b61125a3785d24873354b6e9d1d6676c498a785b9e9ecbd822ff4c7c3020aecb78b63d2ef2ae6eee8f64212dd3d16a29b6522b6befd8620760c3b64958419bdc697c28c675f7e0b08ec2f54b4272 }

condition:
	$a0
}

        
