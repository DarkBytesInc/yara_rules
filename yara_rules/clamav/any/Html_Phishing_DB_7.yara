rule Html_Phishing_DB_7
{
strings:
	$a0 = { 656e206469652062657472[1-6]67657265697665727375636865 }
	$a1 = { 64696520666f726d20646572207a7573[1-7]7a6c696368656e206175746f7269736174696f6e }

condition:
	$a0 and $a1
}

        