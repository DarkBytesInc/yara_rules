rule Win_Spyware_115_3
{
strings:
	$a0 = { bc6603826f39ba7403b4ddb6884e8e6f90a0d88286252b7d93d2f2fc14fa85603fc52df659b7a7d6744b7a965d4f5e75cb2b6f1445e8faee4edbc7500c09ca1d5a3adaa2f6062f014dc039331cd4343d3e213f194cd40b8bd0a0f9 }

condition:
	$a0
}

        
