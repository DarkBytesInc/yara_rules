rule Win_Dropper_Agent_34212
{
strings:
	$a0 = { b878764000bae05d4000e83adbffffb87c764000ba2c5e4000e82bdbffffb880764000baa05e4000e81cdbffffb878764000bae05d4000e80ddbffffb87c764000ba2c5e4000e8fedaffffb880764000baa05e4000e8efdaffffb878764000bae05d4000e8e0daffff }

condition:
	$a0
}

        
