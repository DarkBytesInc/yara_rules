rule Win_Trojan_Bancos_1410
{
strings:
	$a0 = { 3e75833f7e9a42e1c6d7a9296d3f6c17e7058ddd274d678ea0e6cf9e972da513d7190aa9807fea0519afe4442e36b2d65b85ab0396a868b5abeac5f3d889396e19f9cc483ded7d1173eba0fdf0401124ca16c3f928c0bfc3f1d6 }

condition:
	$a0
}

        
