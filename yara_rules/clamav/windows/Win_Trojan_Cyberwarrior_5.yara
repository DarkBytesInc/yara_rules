rule Win_Trojan_Cyberwarrior_5
{
strings:
	$a0 = { abcd33f681c64301565681c6??02b92e312e890cb1042e884c02b946e22e894c03b9fac32e894c052e8a44075eb9e8????894cfa5eb9??0234ff3a2904eb0190e800005d81ed4601062e8aa6??042e88a6??042e80be??04007512909090bf00018db6??03b90500f3a4eb12900e1f0e078db6????8dbe??03b90800f3a4b41a8d96??04cd21b44e8d96??03b1 }

condition:
	$a0
}

        