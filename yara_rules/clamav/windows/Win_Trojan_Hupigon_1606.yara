rule Win_Trojan_Hupigon_1606
{
strings:
	$a0 = { db11808729189a7e6b1325812546451108493048e6de26ff6622ea7924e9ecb4f56a58dd6d6593aaf865986a4da45eaddf4c76624a79c126789127f530fd9c3437e10cb9aaf100e3cba905372e50bc3123b7153f6810f7807ade88ad7fe57fe5b4f3208f7a64f93c8ae84f3efc8c7968fdc979a326fbb78b9836fd1fa4d096df237b4079ac1304f85a1308a7ec78da103b237f2be727 }

condition:
	$a0
}

        