rule Win_Spyware_Banker_3401
{
strings:
	$a0 = { 71039f6a54fbab84990ab47188e6021858d96e99048f9517cb7f2164f404005052e9247057cb461a924799a1ba581987bb0a195a28d8df10e6594c69129faceb5676bb327a69306644bd41be71356572b4026ab1551b99e84701ca5ef5d460f2799646707d198371e11763ab99631cce6b48724a3d9e0f96c6c8b971bd6aefaeed14c3be3da703d27fcd3c5d }

condition:
	$a0
}

        