rule Doc_Trojan_Antisocial_2
{
strings:
	$a0 = { 66203d20284d696428492c20322c203129293a20466f722058203d203320546f204c656e2849293a204224203d20417363284d696428492c20582c20312929202d20663a204324203d204324202620436872284224293a204e65787420583a2041203d20 }

condition:
	$a0
}

        