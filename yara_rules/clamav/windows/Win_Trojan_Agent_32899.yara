rule Win_Trojan_Agent_32899
{
strings:
	$a0 = { 6cccdcbf90cea3b46fbe9520af7fa74c8aa086440d4d609a8cbf13e1e88e31d7bb5b0084e84ce5230f1516b99a6cb13b15519cba6f1255b85363b8ef7e6960932848e709243a753392e32b94643f }

condition:
	$a0
}

        
