rule Win_Trojan_Lineage_54
{
strings:
	$a0 = { 31387d95d2d788f1693ed27d97bf66405ae7d7332baa6695905cf8ba82c9b3974482807062d916257d1e590f330f585fcd28626772b7637e630ff1e6902f727e729453544a429c7df12fcc686a696762526921471b8cce62839f4b494828324a0f9c93490e69756b7104572c6183755345122ff9d0cefad4722761c1189ba14cdd306e72231c72f5104524c4c2e063642b07d02c }

condition:
	$a0
}

        