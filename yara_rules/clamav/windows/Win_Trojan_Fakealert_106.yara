rule Win_Trojan_Fakealert_106
{
strings:
	$a0 = { fccaade4fdd1806f967a75e169f5b770ad5e99106e0c7475da15af8055539dbdd41d2ca8f6138c7ef4b0f3b2cb839a0e48bd94b9997c5c7c9cc22f869201547ecc2fd25acbe4b4f62fc8dc696a4f2841ad9a2e8ee37f64c8dbcdcbc1fd530c81df29239e }

condition:
	$a0
}

        
