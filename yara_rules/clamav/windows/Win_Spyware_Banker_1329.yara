rule Win_Spyware_Banker_1329
{
strings:
	$a0 = { b95146056a54e49c6f43ee08c9ff9f0572c2ff1cc8d5eeb36d9db2a6216dd2eca9f033b2290cddda93172ae892a37edfdf81f1b2f2c1b5bd761320dd6b37971b5dec2eb7bb0686e659eec173af5b63fbcbb4b2ba101ede69700a0f560bc23eb428c64df3db9a22011d6d3849c30a2d37b666c16ff98a6865d93a98ca7dc5bd48 }

condition:
	$a0
}

        
