rule Win_Trojan_Hangame_2
{
strings:
	$a0 = { d920a6a9e8d51a19585a56c2f2230419201d673bc905ea39b715cbb9b57f1da7e925fc3720eddcc80dcdd904b8c056dec80ac8ae37b01f490575cec1ab80bbae456b720b6b9036e5c836d73a3737720bbb99d06fe00eeb9905bb71b5ddccbbe98ffffffc7bfdf3e7dfbf799e73cf39ed9e739f979f3dfe221c36b3488a67b3a04001ec1bfc1f02ce8e02a63b }

condition:
	$a0
}

        