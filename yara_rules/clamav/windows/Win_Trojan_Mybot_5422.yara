rule Win_Trojan_Mybot_5422
{
strings:
	$a0 = { 08c160c0aff722c957fe604db01fc548ec206848ad0ef6967395904d0a3583738d79713660d6229334bbf133392df29a48839397963c6ec6bd645930c3d27c1f9a9dd2f1705e2f3d98cf518c020ba3dfb39bf9e5fd93e2931dd666b455049d7fc7ab25da32efca22f6 }

condition:
	$a0
}

        