rule Win_Trojan_Bancos_1915
{
strings:
	$a0 = { dd02ed0c6c8ddf1c6af4f2f7499b90d00834af0f5552793aceeb5072cce668c69c1b846420959bd89adc4d75469733e93fe2b04bfd4f9f611f12f46b0d4ebed5fa728542debfb98aa2184e3b589c9168c479dfca6af3fc72351a }

condition:
	$a0
}

        
