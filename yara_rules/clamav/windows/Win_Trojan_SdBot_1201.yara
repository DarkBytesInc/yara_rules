rule Win_Trojan_SdBot_1201
{
strings:
	$a0 = { 0bd726f3001642f364e86b59ab55d9c73baefbb86c9edd79f810aa8457b72e38960d6888310c05a732d76cc27c11e0bbda52a1f3ee05cf1b728f1eb6c4c95e7df2eb61010c2a2bfced047935ae1fed9b40442411b2e2d0310eca9ff234a1a08f873645af1f8d1cfbd13e8bd553374f5a76790a62e5b9c2ca70cec1eed3c2dc95155ae1ee721534bce2c6abddd137a30e7b5b859f11fc }

condition:
	$a0
}

        