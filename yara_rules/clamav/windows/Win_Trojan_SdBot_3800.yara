rule Win_Trojan_SdBot_3800
{
strings:
	$a0 = { 1d1c7335047e694d1df4e7b920e335ebed8696454ec4024e7bbbf7f6f9f83e5080fccfcee8af23d5d46e7183cb73056868dfde5a5797e3e2e5e40a5c78d8dbda54eb2c72b0cbaf03b4a751503feb2e8c394282bec1c0c3e93b57b7b6b933e20b518f }

condition:
	$a0
}

        
