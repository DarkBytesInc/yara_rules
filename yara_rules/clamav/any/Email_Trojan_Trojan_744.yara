rule Email_Trojan_Trojan_744
{
strings:
	$a0 = { 4e6f74653a20466f72776172646564206d6573736167652069732061747461636865642e0a0a5468697320697320616e206175746f6d61746963616c6c792067656e6572617465642044656c697665727920537461747573204e6f74696669636174696f6e2e0a0a44656c697665727920746f2074686520666f6c6c6f77696e6720726563697069656e7473206661696c6564 }

condition:
	$a0
}

        