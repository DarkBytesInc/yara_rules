rule Win_Spyware_Banker_5876
{
strings:
	$a0 = { 6315356865b6c8ff9087735a4b77c0c8e2e5551d3e73863333453c1c8dcd25f3ed786961485c48790a46da3b8ecf7b536de0a0dc1383856ffd3c6ab99674dbbd4a93276d }

condition:
	$a0
}

        
