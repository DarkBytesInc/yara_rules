rule Win_Trojan_Hupigon_794
{
strings:
	$a0 = { 01cda7506754ee2eb8fddfc5d4042c37804f7f3b68d472386ad6a1143998b35c25ab6401b7b4431b9e31825a16a49510aee78997abab08a0542c2c57c71cf079e00b91bee07eda0679e5601de32d3eace7eb5cea9a74c3feee7a0bb4449814 }

condition:
	$a0
}

        
