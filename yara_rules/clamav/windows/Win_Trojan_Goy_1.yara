rule Win_Trojan_Goy_1
{
strings:
	$a0 = { 450f56dc5caa7cd07162f4c87f111437db7f57bff14bff00e72e3cc9ae7e41fe4e7e4df93ff29af8f94bcb9a96a7ff003909f96d79a788e3bf2fe5897ced1dbbd8892f96e24158ede31ea86130a57d4a9271ec0c10ed0d566c9a81c52034d92f }

condition:
	$a0
}

        
