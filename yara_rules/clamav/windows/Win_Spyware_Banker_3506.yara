rule Win_Spyware_Banker_3506
{
strings:
	$a0 = { 4c25d0df137db101ac22d2d0d4e251db63b2bdd7a0875c0b07eb3937fca8416f077ef37f4b75b243d6cd93f938c8f37c03a7273e9ed18b44126621027056b1449c394b6c969d8e846988c4bbaf780a490bc9ab1e46ae2a227f5f }

condition:
	$a0
}

        