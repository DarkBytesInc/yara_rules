rule Win_Trojan_Hupigon_223
{
strings:
	$a0 = { 7df63a6602b221a3db66e73c24e69b2ba287e7c1e0d1e37f1087d282e71dc9f10346f47c4dd4df38efe32aabf6d983666a882ef846defcd33c64539407e78c0c38059569e266f4bf42189c5ae8f3c265e9ed1ce7cd588b7497c8aeac04df72c37d162dc15b8d3dc48eee7a1a535e }

condition:
	$a0
}

        