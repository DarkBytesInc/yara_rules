rule Win_Trojan_Mybot_8259
{
strings:
	$a0 = { 4373075269457445b9ad5c86c740f51ed79110de8cc4e74cb61cc320e03f7e0fad7aac4dc237842a4a5a70b50edc8ef637aa46d407a0ccc10e6db72b02df13c94ace78819769304f477c44ac55ef4ed87d541f1da9688ef5d5d1f40a39f7ac38ee89ff }

condition:
	$a0
}

        
