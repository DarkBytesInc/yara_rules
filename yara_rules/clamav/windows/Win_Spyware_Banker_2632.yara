rule Win_Spyware_Banker_2632
{
strings:
	$a0 = { 5a1a52c8c9e908d5bcbbc29007501e0c307ecb45fa9b64c7a3452afaae7e3477f60e0bb19d99afe3935318a895eab759cd910c6d6f93ec50fbee8ff76e62f4329c019568ab124f5ef3201ea227b1ac3afc7a992f8742b2fd63d7e0a6e7664cf91d9f4deb8daadff8aa34e24f }

condition:
	$a0
}

        
