rule Win_Trojan_Hupigon_615
{
strings:
	$a0 = { a1023e325ad715dfa68f498929e7640a604f11982c7e81a04879a6a01c878e236cb2c8b77e0c6383b120fc25da22d1a12590f17c768d92f5de4f6e5d3ca68decfd07c457f34f73d872a8b97dd0a721bb05dbaa8974d547779117cd34da21614337ede234f3211eda68e95de667f3446edb6d700f0d76e6a42ff8e2f6e4a4e82f05bacbf97170 }

condition:
	$a0
}

        