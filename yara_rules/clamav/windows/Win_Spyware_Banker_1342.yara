rule Win_Spyware_Banker_1342
{
strings:
	$a0 = { ae18b7e556f43f35bf3ec4719a6662639de38faafadbc78775177bacf6d8b9af40c88f75bbbe2d119e0f3bb9d0c276d7c302c0dfc3fffce330b768f5fab9be8a02a3a6c054eb19d0fbe15e570ae0f22c976cad0a5998ebe1df2065fff5a58b86eed645fa5e3700adffae6adc98df739d797d898a5fbafb7cd8a9afefbbff7ff2 }

condition:
	$a0
}

        
