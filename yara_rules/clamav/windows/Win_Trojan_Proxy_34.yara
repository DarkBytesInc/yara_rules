rule Win_Trojan_Proxy_34
{
strings:
	$a0 = { 74b715015a2af993f08caa59d15656f0168ffa3778f851b643323058433030d7eb017555a155fe4c66890374f7408cc9abb6ed3c15af105d432173965b515b7b2c72f6990b5b6a80163b7b767df7768fc085a26f8f0f59696b10f7b654e0133ed43385d05d5e573a73b03b193f78483ba3242556a366a0c60c66d93feb2d44805c419cf08f3f37b0b76b0c0e473c66348f10b9afc6eb }

condition:
	$a0
}

        