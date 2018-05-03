rule Html_Phishing_Bank_1480
{
strings:
	$a0 = { 7574656e746520[0-10]20626c6f636361746f20[16-60]616363657373(69|6f)[12-40]2033206d657369 }

condition:
	$a0
}

        
