rule Win_Trojan_Agent_33701
{
strings:
	$a0 = { 7f7aa21d646fffd4e255e2e087811ba2a1f824c6b9eac7b6f1edb52fb86ed62584ac3a5b84ce4a069bddbc72b00be60845e82780d5ca18e28a16fcd5d60271f0352e598a521df947810350b6d3c3fbbe7fc62c876d774fbc63434c6cab52c3 }

condition:
	$a0
}

        
