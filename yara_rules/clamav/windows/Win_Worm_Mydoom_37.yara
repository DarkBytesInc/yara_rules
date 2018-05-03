rule Win_Worm_Mydoom_37
{
strings:
	$a0 = { ffffffff7d93abc5e1ff1f41658bb3dd09376799cd033b75b1ef2f71b5fb438dd92777c9ffffffff1d73cb2581df3fa1056bd33da91787f96de35bd551cf4fd155db63ed79079729ffffffffbd53bbc021bf1300a64bf39d49f7a7590dc37b35f1af8f31fb9a884c1ee7b7a9ffffffff5d330bf5c19f7f21452b239ce9d7c7 }

condition:
	$a0
}

        
