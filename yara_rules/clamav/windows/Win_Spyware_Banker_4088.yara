rule Win_Spyware_Banker_4088
{
strings:
	$a0 = { 2a054bd1068506057cbfc60fdbe3e21d99ffbb281521704209f486ee0f9d4888589565607dda21764d13df78688e165c158e2f05096643a7b4acf3b261aeb3542a3a2d4657a79ec6095e50cfaf98b212cacee7f1a3cbc10c6ea8827b41c3857533f5780c39a60feaaeaa5b41077c9790fd9cdc70c535e7c935ae9013ab48aa9e01d17e9a5183509871f5eb32 }

condition:
	$a0
}

        