rule Win_Trojan_Fakealert_105
{
strings:
	$a0 = { 17e53a153fb5c52b0e0527d30abdcf2d7395ab4c0c33253015ae22dcfadb21c5ee2937a6f72891e0e72f37beb21aec016b76b0153eb5c6240ae9ce710abdcf2d0cde3e512151d23017a009bc3fc411ce0ef25dbc0b8479c7bf19601b02b3e14b22b43b24 }

condition:
	$a0
}

        
