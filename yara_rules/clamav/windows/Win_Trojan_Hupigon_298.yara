rule Win_Trojan_Hupigon_298
{
strings:
	$a0 = { 34766b54bf16dc75ba19553cf4f41864deacf02946d7ddd2fd11778d63b7a9e8ef4337dfbcd46d4aad2ac2946686d5c8d6aa037e8639cd5acfb448eea850ce28c195dc63c6f6fecceba45a57f15ed1e632cc217b9f4c5c9d5d58 }

condition:
	$a0
}

        
