rule Win_Trojan_DNSChanger_148
{
strings:
	$a0 = { b46b1c09ab8719a5211ab61e5e704af65dab567f9b9b73ab22a80f0ed86f4af6d1ebc9f6de6fc18b2a54b182a2871cf1de6fce36aa5420f453e90af3de6f19a58ee65209ab93b58332905fcecf2f4aa6217af2e69e6ff3dc942f4a4e5a280af6f5a71ba6 }

condition:
	$a0
}

        
