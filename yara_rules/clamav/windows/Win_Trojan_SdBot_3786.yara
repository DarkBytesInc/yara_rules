rule Win_Trojan_SdBot_3786
{
strings:
	$a0 = { b06b6b6b6b20f1cc6b6b6bd4b8daaf6c54912f6c6cc5c5f12c7bf10a6c6c6cf7f1b06b6b6b6b20f1d06b6b6b5425306c6cc5bc5409116b6bc5ef646de18ff7f1b06b6b6b6b20f1d06b6b6bd4bcdaaf6cf9f114636b6bbc540d286c6cef3078578df7 }

condition:
	$a0
}

        
