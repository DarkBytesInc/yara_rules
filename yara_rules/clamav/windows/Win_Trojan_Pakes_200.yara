rule Win_Trojan_Pakes_200
{
strings:
	$a0 = { 3171039b21d6830220f8d801df7c7b31135851e54c5588803e357d3efa09722100ed372ef3684a80b393c40ce548390303b661a9b2234d8053d875181b8936a1bc5c03626aa3fce53501397536c4fa1cd2d872700ec19ac5fc09908240b8d14cb030749a51d451d900cb8fef725b91939c03bd702f893aed2629ab10605f3c703203ba1796406e74a629074e }

condition:
	$a0
}

        