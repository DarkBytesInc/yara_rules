rule Win_Downloader_Zlob_2273
{
strings:
	$a0 = { e8b23373dbd55bdba58acbdc433b0a41a00afcb0f3ae531c3a14dfed2ff99de7b354e2640a17f134ac89c91c334b4ca5409d7f8151d6852ae61fb4254188bed391b5c5bbadb303e43691ab1a40df20384a737b94f54e53d8f260 }

condition:
	$a0
}

        
