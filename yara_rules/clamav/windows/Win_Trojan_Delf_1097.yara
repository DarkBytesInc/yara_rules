rule Win_Trojan_Delf_1097
{
strings:
	$a0 = { 01c3ffffffff17000000796f756d6569796f7567616f63756fa1a3a1a3a1a3a1a300558bec33c05568f148400064ff30648920b8a4504000e821edffff33c05a595964891068f8484000c3e9aae7ffffebf85dc38bc00c00000004494000843d4000543d }

condition:
	$a0
}

        