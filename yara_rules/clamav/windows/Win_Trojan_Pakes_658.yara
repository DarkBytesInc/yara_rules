rule Win_Trojan_Pakes_658
{
strings:
	$a0 = { e580ba98592ff72c9afedc78609bece165dc9ceb416847b1657487600676d93a7cc59a7dbc94d2cf506fda67e06eb1726934c7471f23d8717029ab6693d1df0784709e5d60742ee13171efb3d342c8423a24dbf376e2c74925149ad54c955c88ed712668d31e18b570c9cc6a4f00bee9e539a3080bedb1ddbcf8d2205177d25f0311a71e127b86671bf04b78 }

condition:
	$a0
}

        