rule Win_Trojan_Small_5309
{
strings:
	$a0 = { ae8a2fccc6e0abdfeeda0272afdd14f0c1caac5c96fcaf07ae0d7020adffd01fada0b417ee8a0b660be605cb04e21408be8aac71b689c13fbecaac57ada0e817ee8a37f8188b162b04f5ac06c4debc47ae0f6c7ce015e937becaac5dad6231c822b00207860b2838ade72110048a838812bbab }

condition:
	$a0
}

        
