rule Html_Trojan_ClickerDelf_13
{
strings:
	$a0 = { a9b4aa6e055125dccf8ccdbd7c7e257487c4309b4af21c1feb9f2d003447714e4a41ca5c5a16c5341eb79926100198af250fbc3bb0b92ac1767b27e791f409e62ccbc6af224d9438d225fc475466107f4eb0037fcba23207e93c9c6dc22bbd1482a9d4e4b5244f0ab703730e98e5e392bd95e10b2aa576b14688d8831810d98493683ca987ce2830875ae85b1324e6eef61718a0fe6c }

condition:
	$a0
}

        