rule Win_Downloader_Banload_1933
{
strings:
	$a0 = { 593e6a46d025f6f42aeaab4ba5d8c2fce808ccdaacd52a3f63df8a99d4dc17ccfcc456802d87530a259ae34421afd7457692d7089d6ec869ff4f23cda5bd8bcca66c787210b9cb287004497235f1c12d6152d76cc001d2b3ff53730e52aa24113cecd0a77626e90c09aad81f47550ccaf90d164aa5de5f9e216b8dfbe53d500456c04ac1e2 }

condition:
	$a0
}

        