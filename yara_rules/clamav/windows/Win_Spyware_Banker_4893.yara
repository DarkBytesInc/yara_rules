rule Win_Spyware_Banker_4893
{
strings:
	$a0 = { 3127db7ebda95283079f1976c319bbd6928d911594995a20d9d8b026d85f9a02c7546e682f5aca54c1d0cc1a137a7e3782ae52a4d5933a227f19606f9327ab6d4526a7971a1d39819443bb36fdb2613ac6fbc7e5461f42816668d9a38d90a89558d55bdcfbbf19d8d715a5c7091feaa88607d636f11f8834d25b3e718583598b2221cb967089100b9ff6fd3a0cd16d8c3ca2600fc069 }

condition:
	$a0
}

        