rule Win_Trojan_IRCBot_464
{
strings:
	$a0 = { a073587540ca44c363d3fa14e73c211784a30c89af3971068febc7f0da6655fd759ea9d079d5aa6b588c9e746b2fe36ef49eb1b09b5139d323c0b296bd5ce25b87a0522896c51bd3c75424bcfec3a59e4eb44e08fe3ce86c46a28172fbea359f9f627d2022bd4e037e94b8bf7b9872aa7461603f7a3e62de298a5f2a0baeb8e3d060e603d0f63b8cd5b70e6030459de3436ebf2af649 }

condition:
	$a0
}

        