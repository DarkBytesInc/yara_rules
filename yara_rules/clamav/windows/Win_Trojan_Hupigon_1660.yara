rule Win_Trojan_Hupigon_1660
{
strings:
	$a0 = { 2fb2451190c1c0bbf6f8c39982e9e091d90fc76d662e1ca5aa9dffa8349097747e56531d9287aa2df23fa97b209f83f6814ec67efc2e0a0adeaf58a2849d68eba0846e56876defd309c9bf29869420b6c91bc0f71bb78f1e }

condition:
	$a0
}

        
