rule Win_Trojan_Netbus_37
{
strings:
	$a0 = { 2a35c6c53e46a1bb430addd6f80aa438200138ec4de02576b7b18a941eb465bdb8d2e97d3a3d2517972b2aa2b8cc1bc58fccffe01ae5317b9524871eb2ebaa3c8f8ffeef7421853b3010539a8a80f852b40dccc17e43d36127cb22ae05ec0acc7bf83c16 }

condition:
	$a0
}

        
