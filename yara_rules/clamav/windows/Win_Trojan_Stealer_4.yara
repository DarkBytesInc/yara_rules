rule Win_Trojan_Stealer_4
{
strings:
	$a0 = { 249c0381380f20c120bcb5e3d25e9118a4162c275824831582fbce4fd0111973257bef7963db2f5e47636c4b07923670f670ecdbb1ca6e766ee054b9d2ee99dd9711af056db024a41d4ad1a97acdd4dce9dcd2e58611cecb5b565ebf8e7befbe1ce7920958b9ab4b6eee35cdfe4bdccdcc07bbdef617ab8f2443ac0b5a }

condition:
	$a0
}

        
