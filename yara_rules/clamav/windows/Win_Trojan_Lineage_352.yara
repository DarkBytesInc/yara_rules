rule Win_Trojan_Lineage_352
{
strings:
	$a0 = { a48799e444a89d07c5af79c2df9bb6eeca022bcf8e0f58c3a1eb608b68c4c6644f4b8948b088c041ea2fe2afad4c11fd856c3742051b6b0ba051dd1379edd11f3de49975a3e27f7e1595ffe9bccfaf4019c9862bf44fdf42270399f7f758d34a5a2cdcd2d8b22cb23813ca97 }

condition:
	$a0
}

        
