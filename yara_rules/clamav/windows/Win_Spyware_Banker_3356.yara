rule Win_Spyware_Banker_3356
{
strings:
	$a0 = { 47fed7e056ce2f3646ba336a79c75cc505821d3d9c7f4266c249bf523ce29fbe4e8023da9c0dc056c02745659f7fad13af01b1cbd366e8680d8f99b8173a36f994e156f6ed1ca5ffebf60b6c2036e99febef4b9f16 }

condition:
	$a0
}

        
