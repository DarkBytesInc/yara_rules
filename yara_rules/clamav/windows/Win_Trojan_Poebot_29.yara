rule Win_Trojan_Poebot_29
{
strings:
	$a0 = { 56a79e042171dda653118e49f25952b202cc1ce601a17c6fe6e76b42341a6242bae93cc33268693b764b3d01d8797332687a009b6dd69a3273747e6b757931f9595eb71c7db257d605b75c7859e63a7f2a11ee2f0d9a9ba7ed78cf774269777a46737d7c4d2d2429e174462a3d737c464dac447376774d6843e72db62f4d4077787d2a0d79466b69714d7d44021de531e1637d45017c }

condition:
	$a0
}

        