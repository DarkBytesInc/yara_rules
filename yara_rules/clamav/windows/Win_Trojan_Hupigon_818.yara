rule Win_Trojan_Hupigon_818
{
strings:
	$a0 = { d302b6b98500e487128e48a1fd1301c6d20344866acbc657c9082266ded28ee83724c363907df8fd7faca0b8cf20cbb005e59a5b757ee7e6affe5371b1ec9fce6237dba747da94b5514e82902c57a46c8e53e80fd367a8fe05346a6ea96edc }

condition:
	$a0
}

        
