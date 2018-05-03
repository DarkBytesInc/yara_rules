rule Win_Worm_RDevil_1
{
strings:
	$a0 = { dbffff5562616842726f6e746f6b005265621574f8582138bcb7276146696cdc9110 }

condition:
	$a0
}

        
