rule Win_Trojan_Pakes_602
{
strings:
	$a0 = { 0a16e11c8e6c9b70519c863c8700b7b38ab9c6ada62d0b048a21cb34ed23817e73d2c03f330279d1972c8039072cd9467e618b59d4788243776eef3a58c783996b26c45f872174b4b626b30518589256b1717fc57db78b4bca81c0e7a302070d02276c2d187c420877ce962ea495e4ab0a5fe78ce0aad9df339e787496247861e886eba2d920cc39d0a50f3d }

condition:
	$a0
}

        