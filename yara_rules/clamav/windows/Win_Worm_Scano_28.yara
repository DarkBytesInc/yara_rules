rule Win_Worm_Scano_28
{
strings:
	$a0 = { 2273657466736f3d6372656174656f626a6563742822736372697074222b22696e672e66696c222b22657379737465222b226d6f626a222b }
	$a1 = { 7365747368656c6c3d6372656174656f626a6563742822777363222b22726970742e222b22736865222b226c }

condition:
	$a0 and $a1
}

        