rule Win_Trojan_Spambot_76
{
strings:
	$a0 = { ef3b9dab1a819ed2b21a138d302b97c79c22bfe69e1e40fffee9ffbfbb2e4a7005093a79f47c9970a5ec4bf8d941a6e25256feffffff120d7ea316ae6ecdbf809f1861da3ffab7a8ef54874034e24c1a2c2c50268cffffff2f45b552255336600a7994c6c9fbc6441604e9916a0e }

condition:
	$a0
}

        
