rule Win_Trojan_Mybot_7019
{
strings:
	$a0 = { ed507f7b47f5a9c32b433d4bd85cdf0c2ad1b5c4e1b15061b7f2c3dd876e095ba4a29839e1c15565315fa8e3423195ff1873475be7f7ce6b403e2a84a7431488305abcf09c72b35582384452e469fb514354b9a188587660e4db269c2dff2f8965a0cbd49406c9e27d5c6f666f56907a067347e653433c13cd161de1ecf1f7ee90d451e93cddc556ed96bbc85590d1bbae803249ddea }

condition:
	$a0
}

        