rule Win_Trojan_Agent_33643
{
strings:
	$a0 = { 5fb7bd868b550ba7d6cf8e2c0ab65a5dc0c276f6ac2f4f58e612f603467a398592c95705dc861cfcd51f9d32940fbdabec7871446671c0b777ecf2261af13c9be49e2a17e9af67a3590568d84a520b326e84 }

condition:
	$a0
}

        
