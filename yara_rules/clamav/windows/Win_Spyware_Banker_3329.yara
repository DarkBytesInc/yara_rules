rule Win_Spyware_Banker_3329
{
strings:
	$a0 = { 28b1fe5a45234d5fd1bf808e2dab83648f6dc18c5a2c1db3582adba3fe347d78c38a8d7c0811ffc604c863f44cf421fad6eace7d5d72e7bbf46e40b894621a675c5dc500f72011fc3512e782c282df3b4b7fedff3d }

condition:
	$a0
}

        
