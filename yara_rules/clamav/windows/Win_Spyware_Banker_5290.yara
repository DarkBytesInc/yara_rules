rule Win_Spyware_Banker_5290
{
strings:
	$a0 = { cc46dc69b797244894180a1f4dbd2e58e8b6b65dcf612151bc06c6ca1dc926ea5aae29f0f9039b8b789ffdc044a91706fed7856565ebaf889643806b7a49f1a3b117e6fc48ddb6bea3ded9bb01a7b511d6448f4377e4bd3d353ade323c5e4c6150049ccc5d1beae0b3a23523b966588b8bfdd533dccf6e1fa2cf80908658e0bc726fc14d5e6f9432f7978c77de6bfdac407210395429 }

condition:
	$a0
}

        