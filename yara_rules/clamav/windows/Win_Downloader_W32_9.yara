rule Win_Downloader_W32_9
{
strings:
	$a0 = { 61d93e5664ff2f36ac3a7c02080402cf4538524c89e2ac48e1ffffa09f143f820097f9e8485d1081f633ffeadd84f0ffff9f776912a203bd07ad7a3182ffe09b04750bb68ff2545d0263c3faff318b38 }

condition:
	$a0
}

        
