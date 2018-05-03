rule Win_Worm_StrationDQ_5
{
strings:
	$a0 = { 4a565f4d4e584b5c4554707a6b766a767f6d454e70777d766e6a39574d455a6c6b6b7c776d4f7c6b6a707677454e70777d766e6a }

condition:
	$a0
}

        
