rule Win_Trojan_Small_1248
{
strings:
	$a0 = { 4bee14a10ff914ca229684f6490e46376c42342664df96ebe367dee0ceb3474c7259c8d4d719685e6da728bf5ffd4b88a59db0195820663ab8613e9ddb49748b5c9bac08591dfa5e87cafa8bc2e55b02695ab6b383753111dda1aa1927d4a90b2a883b7349542eb13ff96bfc58bc49c200ad7f241f9798c07932a8a352c1bed299bb422cf90243884738a193c3b1668beb036416a407 }

condition:
	$a0
}

        