rule Win_Trojan_IRCBot_510
{
strings:
	$a0 = { 42f3f5e0ad48cb9fa47ed007eff9dbd13f72eb0c5a2f4ca14067ae7109d485e2831149224745c974adae95d23fd4db5bc157e9e202ff9927baca33fd65d1d80e08bea8fe35506ad0c2871fdc188ac650bc2960aeacf57f72c48e29fb27bdd80663f8df7f692d386d06d0cfd328f9da88d8163afc9147c554bddac74ef671215f4dceca5016cac36b2b54e1b94ade87f90cccc5d8898a }

condition:
	$a0
}

        