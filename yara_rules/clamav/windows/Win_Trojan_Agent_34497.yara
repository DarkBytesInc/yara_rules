rule Win_Trojan_Agent_34497
{
strings:
	$a0 = { 8b4608508908275a5033c089c14d99700c105e81c002606aff682bfc400064a100506489250004c032e181ec340053555633ed57558d541300c3486a205055ff15e81168262016bf304083c9ff8d02b40b00542444f2aef7d12bf96800108bf78bd98bfa0560bad98bcb4fc1e902f3a56eb12f8ec714f400262083e103f3a4a48bd344ebd83c504259383c94 }

condition:
	$a0
}

        