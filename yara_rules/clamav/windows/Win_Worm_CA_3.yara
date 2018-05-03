rule Win_Worm_CA_3
{
strings:
	$a0 = { 0a9ffb6f1d00de2b69a66331f3e3e0af8919d9f43c169abeee8c1dd03aa96158ab23053efd93e307fa3c25e9a3981eedfe6f74f92a6ef44c34518c7c8f056fee0722f99bbe8163d826f93f1d2e35a3d441a1f6c0d802932d2d1c9b52654c141ddddccdc467a7a94d81b1dde0bf359a31 }

condition:
	$a0
}

        
