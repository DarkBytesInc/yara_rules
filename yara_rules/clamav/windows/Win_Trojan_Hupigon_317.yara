rule Win_Trojan_Hupigon_317
{
strings:
	$a0 = { f2c527d83c21b74026a4dc1e95c11e50f23f34fb0d58215f156101e0c3cfff9ad08bb8e38848d6c27eb01b187e8e79d1ba89c300b7e7b1a40ca0ebf3a853cc02302e6dbf44c908d0eac505a0bbcbb8d42f35032370977652c39f }

condition:
	$a0
}

        
