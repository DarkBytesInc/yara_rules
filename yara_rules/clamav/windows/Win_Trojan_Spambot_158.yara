rule Win_Trojan_Spambot_158
{
strings:
	$a0 = { 862738835d78ffffffffaad71e4b2df92044a0f169d5fb8e1ed850a643cf977e495e83a0b2ea8b72acadffffffff29af06ffdef70ee3961b88e486cb97fe51ac9830f195311f64cfe7c2f3b22d65ff07e2ffc222543481a3acc3ca6d53d98b8ac62624213f04ffffffff809b7434 }

condition:
	$a0
}

        
