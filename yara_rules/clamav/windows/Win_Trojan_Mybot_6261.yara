rule Win_Trojan_Mybot_6261
{
strings:
	$a0 = { 5581ec1c0800008becb81c080000908804043d000100007c04c60404004875ef880404e9df0000008b85040800008b9d080800009003c33d080000008b85040800007c07bb080000002bd8899d0c080000b9080000008b95040800002bca2bcbb5082aeb }

condition:
	$a0
}

        