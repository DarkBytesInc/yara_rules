rule Win_Trojan_Hupigon_856
{
strings:
	$a0 = { 7a36f8d1e7f2919ded27990f4a344bea6de6db1c2814ecf5be2a769c64457754c678cec5d5b8c8632eb90a5bafb95f24affe3bdbbe2c4472417ac52ed7e42d913b29c2fd8a7190fc1ab00e49525fd1c1400339b166251df854f5818e375458 }

condition:
	$a0
}

        
