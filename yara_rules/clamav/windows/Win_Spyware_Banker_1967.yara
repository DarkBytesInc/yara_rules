rule Win_Spyware_Banker_1967
{
strings:
	$a0 = { 7f7d1cf19e5a59636ec201b308d6dc175fda3bb85e0edd873a5862a94a4fe7634b62cdb686cd4c28b78fc76ae5e9ae6091831343aeffdc1a208166f616ea76a79024a3421bbae4f532cb9487dfd65b4ecf7ed8bd414d63f2ac7e2a8ca61cb556859879ec6b8cbe15e7c90aedc073e535c43c }

condition:
	$a0
}

        
