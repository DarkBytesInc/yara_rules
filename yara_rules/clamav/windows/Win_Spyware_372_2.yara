rule Win_Spyware_372_2
{
strings:
	$a0 = { 73464c5b5bd050c6082c5322962351cd29b20131c56c124653ee9db243d3879b11ba6370797438ce150c05fec9bc88730584d9a64dae48a648cfc3091efc3061951fddea51fdae1955b2aa2341238dc4415dfc89ffd0f3c270f2ebfd13526d1e01e2f50342919cf1aaa30c6b144ba53a1dc682b05322d222316887c8cd93192016e785eedafbbac138d669fea8d4c084 }

condition:
	$a0
}

        