rule Win_Spyware_Banker_1160
{
strings:
	$a0 = { 11b2669ef4fa2df0dde2d7f1b17e3dc58f63cbfe034472308c078fa5eb5ce1b2ba58cf213681457040a95e0d7960cc13bc116a6162f197f470b0218325537acd1a6d3e071e09b81ce9de4c8b53e4c6b9ec4b97dba67136f9d844 }

condition:
	$a0
}

        
