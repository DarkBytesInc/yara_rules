rule Win_Worm_Bagle_2
{
strings:
	$a0 = { 47c917fde35da241d9af75fc53f018483d5a81f32a7d17f429b1c2e56dc63160582c1836389f4c2f02c3dc579f64b26a7d406bda54fb9761239af091a08552ae75d5515f158f23fd6b1233a51fc0ffac }

condition:
	$a0
}

        