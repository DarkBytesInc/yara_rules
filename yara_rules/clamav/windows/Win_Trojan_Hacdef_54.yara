rule Win_Trojan_Hacdef_54
{
strings:
	$a0 = { b21daee9631172f1209024f1b87b57b1ea829e8211ffa2a1c8c8e83cb8dcc0d845205f158a3e22a3d1ad82b429cac77418c428bf73847c0bb9f05568c3c6e97acf22a9c5953b2c3ad9f9dde95b3057685ec62be3b90f5441960b }

condition:
	$a0
}

        
