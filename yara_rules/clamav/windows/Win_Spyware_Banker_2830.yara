rule Win_Spyware_Banker_2830
{
strings:
	$a0 = { bd9825babcd188e934802d556e9d402b54a4a049553e4a91b2ca1e93047818d35b5d6d403c26ecddb64c5e5b2472ec1316960a49c5b04bd630544f362a10d79b606b28c79ae92b287e9874e53690bf4fe290d2ff6be0b4ad80d2b61ad6a990b5be7454f3d0d6eda0e224335f04b34ad31634bc08d369e6596475f66edaca4e8f9c6b6c6542e965f2a6727a49fa545d34 }

condition:
	$a0
}

        