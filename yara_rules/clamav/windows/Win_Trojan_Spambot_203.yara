rule Win_Trojan_Spambot_203
{
strings:
	$a0 = { fffff073a6ab119a92b1a25e9e2bed0e5ac4a4b92215c5c17bae69eacfa4c52414dbffffffffdd2b6fdb8406d99db34d7ec1bc6df0a56c03378125069b61a94506dc3ce162f9f8ff50ff7ead943b46a26c51673e55aaf09dc62cc6a0a091ffffff07b552e2da13eca2df68995626 }

condition:
	$a0
}

        
