rule Win_Spyware_Banker_5969
{
strings:
	$a0 = { ed61b2041d61acfcc0d0a87dde97573c665b8deda5d38e5c768072ca988e388d2765aaee389c72d50430a56b1fc056c2441f1b8e3dd3e5ab3a4800f7a55e21f9a3de0aa1cd99c06d426c663d57f554f42146700cd6a6c359ae97250df02b38cbc5efd6db7cf5bc1cec789408455e101cac1af7e99f924449e221f51422a1cac21122ff6d9adee44c3615799b }

condition:
	$a0
}

        