rule Win_Trojan_Pakes_948
{
strings:
	$a0 = { ee90d22152a5f3e768780306b5de8169c75bbcee554d39039c621cde9b198f2d4626e3b281c0d5c99575293d82b6aa6f6ce37244ed1fdda8af97603ac35253c242ae76d6015f58de97ce5ca5b2c2d79faa268549ede73bfad20da40efaad177b15bd75ca1536e5a77dad9472f9cccf7b8d72c9c1e36898acb413ef }

condition:
	$a0
}

        