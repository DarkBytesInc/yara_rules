rule Win_Trojan_Hupigon_871
{
strings:
	$a0 = { eef431e58ce9538a81b17b25c244bac2f5f5a0e988141564a7abd0d8811731eb6f7b6b1294c682c1bf3cbc5f8d82cf4cffebc95d1698f9d97c980acd4cba0b14c1603e9f86b9b25bfecadd837017c42f12a59726d80b2742d32d66ae4b1eea }

condition:
	$a0
}

        
