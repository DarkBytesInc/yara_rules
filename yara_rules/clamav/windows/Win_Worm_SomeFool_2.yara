rule Win_Worm_SomeFool_2
{
strings:
	$a0 = { 28262426002026242628362522aec398f710df38423001efe08e8e948d00919a93d59181809e3a82cfa2d0a7a5babbcd22ecea8b838f92949e3850cd881a8487884e89c0ee8d8a8b80c84b98941df015c38ebad8ce45c0c6cea4ff0c99cbdba8f6f8fd50ebbd }

condition:
	$a0
}

        