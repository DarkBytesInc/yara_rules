rule Html_Trojan_Agent_36785
{
strings:
	$a0 = { 6972632e6173636e65742e62697a20687474703a2f2f7777772e6173632e73682f20616c626f737320706172616469736520616b612061736372696d657a20616b61206173636e657420616b612061736320616b6120616c62616e69616e2e73656375726974792e636c616e }
	$a1 = { 247830633d2478316328757074696d6529[0-100]247831313d245f7365727665725b227365727665725f6e616d65225d[0-50]247831353d407068705f6f73 }

condition:
	$a0 and $a1
}

        