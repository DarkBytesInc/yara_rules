rule Win_Trojan_Agent_34928
{
strings:
	$a0 = { 22d8bccd2d89fc28f9c0b0c15bb5b0f163adf932b1ff609116e19ced136b352969fde0f06aa5ddb060e8c8be2bfb0228b982bcf162ce8e0d58dbc6b9774db465db9bb3c96df88bf173e5b3dd6c8181ea52a39c655926984758c4 }

condition:
	$a0
}

        
