rule Win_Trojan_Agent_33990
{
strings:
	$a0 = { 8bee64a90884e5ba59e70af4ba7abd14fffc21e53d0800488d957f37c7cac1dc36f13e4ca1ea6ab0b850f5aeffe6d4c60cda8eaa3d120fdcee48da7e0d96965192d1b096b52af1fc02d1253833491c8b4b5ed1d6d75a04faaf58947e67ed8ca7468fc15463af01ec6222407381f62be0bae04dea6fdb54e0bdda64683bd3df9433af863e4ba92cec51127d34 }

condition:
	$a0
}

        