rule Win_Trojan_Hupigon_234
{
strings:
	$a0 = { da30cab337c8cc7404e60674d3aa0664f9f3cf5c072b2dc0b9fac65f5315dabd7e4b2e570b34fd25ebc0792cee0114eea414541cfabb7bc77c45672ab2f31effbb86f90633975f1953886edbcdc3891bb0274fe0d86c265777a03a13cdfa0dbf9fe9f65308ad6b0cad }

condition:
	$a0
}

        
