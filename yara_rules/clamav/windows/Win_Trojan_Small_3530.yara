rule Win_Trojan_Small_3530
{
strings:
	$a0 = { fb74bbb980fcb7fbe7f73a346a5983b0aeb40f827734e35fee4a4d98e55463dcfbe2e346427e30697958607a34088ca49f5fcad0794e1183c9a7189db2c181fdc787a28ed2b4f262825734309cd65d0beb5c150ff26dfe607363590bc166247cee8baa4305ab94984807397b30060a64f4010767e22fb74a68213334678b9907 }

condition:
	$a0
}

        