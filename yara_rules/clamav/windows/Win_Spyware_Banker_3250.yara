rule Win_Spyware_Banker_3250
{
strings:
	$a0 = { 65c990fce2d5d494436012587c2cb621846841af7c2422bc34d1cc19c5cbccc259c98c83a00a329155b4aef0bcf85b8bfe23e3a9b8c137ca8e1edade3cda4bce44e7b81c6682cfcfd39cd5cd27f4fb4f90f5887a645495c778233d0275367877c9feb00f17c8da09cc4f86532c93e8cf10649e03fda4ab12577cbd32443d513feed4c8a364d5d3f4baf9e6b6 }

condition:
	$a0
}

        